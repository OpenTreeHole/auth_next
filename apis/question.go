package apis

import (
	"fmt"
	"sort"

	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"
	"golang.org/x/exp/rand"
	"golang.org/x/exp/slices"

	. "auth_next/models"
)

// RetrieveQuestions godoc
// @summary Retrieve questions
// @description Retrieve questions
// @tags question
// @produce json
// @router /register/questions [get]
// @param version query int false "version"
// @success 200 {object} QuestionConfig
func RetrieveQuestions(c *fiber.Ctx) (err error) {
	userID, err := common.GetUserID(c)
	if err != nil {
		return
	}

	user, err := LoadUserFromDB(userID)
	if err != nil {
		return
	}

	if user.HasAnsweredQuestions {
		return common.BadRequest("you have answered questions")
	}

	version := c.QueryInt("version")
	if version == 0 {
		GlobalQuestionConfig.RLock()
		version = GlobalQuestionConfig.CurrentVersion
		GlobalQuestionConfig.RUnlock()
	}
	GlobalQuestionConfig.RLock()
	questionConfig, ok := GlobalQuestionConfig.Questions[version]
	GlobalQuestionConfig.RUnlock()
	if !ok {
		return common.NotFound("question version not found")
	}

	var (
		questions         = questionConfig.Questions
		requiredQuestions = questionConfig.RequiredQuestions
		optionalQuestions = questionConfig.OptionalQuestions
		number            = questionConfig.Spec.NumberOfQuestions
		inOrder           = questionConfig.Spec.InOrder
	)

	var questionsResponse = QuestionConfig{
		Version: version,
		Spec: QuestionSpec{
			NumberOfQuestions: number,
			InOrder:           inOrder,
		},
	}

	if number == 0 {
		// send all questions
		questionsResponse.Questions = make([]Question, len(questions))
		copy(questionsResponse.Questions, questions)

	} else if number == -1 {
		// send all required questions
		questionsResponse.Questions = make([]Question, len(requiredQuestions))

		for i, question := range requiredQuestions {
			questionsResponse.Questions[i] = *question
		}
	} else {
		// send all required questions and part of random optional questions according to number
		// be sure that number == len(requiredQuestions) + len(chosenOptionalQuestions)
		// if number < len(requiredQuestions), return error
		questionsResponse.Questions = make([]Question, number)
		optionalQuestionsNumber := number - len(requiredQuestions)
		if optionalQuestionsNumber < 0 {
			return common.InternalServerError("[retrieve questions]: number of questions too small")
		}

		for i, question := range requiredQuestions {
			questionsResponse.Questions[i] = *question
		}

		// shuffle optional questions
		if optionalQuestionsNumber > 0 {
			chosenOptionalQuestions := make([]*Question, len(optionalQuestions))
			copy(chosenOptionalQuestions, optionalQuestions)
			rand.Shuffle(len(chosenOptionalQuestions), func(i, j int) {
				chosenOptionalQuestions[i], chosenOptionalQuestions[j] = chosenOptionalQuestions[j], chosenOptionalQuestions[i]
			})

			for i, question := range chosenOptionalQuestions {
				questionsResponse.Questions[i+len(requiredQuestions)] = *question
				if i == optionalQuestionsNumber-1 {
					break
				}
			}
		}
	}

	if !inOrder {
		rand.Shuffle(len(questionsResponse.Questions), func(i, j int) {
			questionsResponse.Questions[i], questionsResponse.Questions[j] = questionsResponse.Questions[j], questionsResponse.Questions[i]
		})
	} else {
		sort.Slice(questionsResponse.Questions, func(i, j int) bool {
			return questionsResponse.Questions[i].ID < questionsResponse.Questions[j].ID
		})
	}

	// shuffle options
	for i := range questionsResponse.Questions {
		options := questionsResponse.Questions[i].Options // copy slice pointer only
		rand.Shuffle(len(options), func(j, k int) {
			options[j], options[k] = options[k], options[j]
		})
	}

	// clear analysis and answer
	for i := range questionsResponse.Questions {
		questionsResponse.Questions[i].Analysis = ""
		questionsResponse.Questions[i].Answer = nil
	}

	return c.JSON(questionsResponse)
}

// AnswerQuestions godoc
// @summary Answer questions
// @description Answer questions
// @tags question
// @produce json
// @router /register/questions/_answer [post]
// @param answers body SubmitRequest true "answers"
// @success 200 {object} SubmitResponse "answer correct or not"
// @failure 400 {object} common.HttpError "already answered, or bad request"
// @failure 403 {object} common.HttpError "forbidden"
// @failure 500 {string} common.HttpError "internal server error"
func AnswerQuestions(c *fiber.Ctx) (err error) {
	userID, err := common.GetUserID(c)
	if err != nil {
		return
	}

	user, err := LoadUserFromDB(userID)
	if err != nil {
		return
	}

	if user.HasAnsweredQuestions {
		return common.BadRequest("you have answered questions")
	}

	var body SubmitRequest
	err = common.ValidateBody(c, &body)
	if err != nil {
		return
	}

	var version = body.Version
	if version == 0 {
		GlobalQuestionConfig.RLock()
		version = GlobalQuestionConfig.CurrentVersion
		GlobalQuestionConfig.RUnlock()
	}

	GlobalQuestionConfig.RLock()
	questionConfig, ok := GlobalQuestionConfig.Questions[version]
	GlobalQuestionConfig.RUnlock()
	if !ok {
		return common.NotFound("question version not found")
	}

	var (
		questions         = questionConfig.Questions
		requiredQuestions = questionConfig.RequiredQuestions
		number            = questionConfig.Spec.NumberOfQuestions
	)

	// get all submitted question number and required question number
	submittedQuestionNumber := len(body.Answers)
	submittedRequiredQuestionNumber := 0
	submittedOptionalQuestionNumber := 0
	questionMap := make(map[int]Question, submittedQuestionNumber)
	for _, answer := range body.Answers {
		id, ok := slices.BinarySearchFunc(questions, Question{ID: answer.ID}, func(q, t Question) int {
			return q.ID - t.ID
		})
		if !ok {
			return common.BadRequest(fmt.Sprintf("question id %d not found", answer.ID))
		}

		questionMap[answer.ID] = questions[id]
		if questions[id].Group == "required" {
			submittedRequiredQuestionNumber++
		} else {
			submittedOptionalQuestionNumber++
		}
	}

	// check if submitted question number match
	submittedQuestionNumber = submittedRequiredQuestionNumber + submittedOptionalQuestionNumber
	if submittedQuestionNumber != number {
		return common.BadRequest(fmt.Sprintf("question number %d not match", submittedQuestionNumber))
	} else if submittedRequiredQuestionNumber != len(requiredQuestions) {
		return common.BadRequest(fmt.Sprintf("required question number %d not match", submittedRequiredQuestionNumber))
	}

	// check if submitted question answer is correct
	var wrongQuestions []int
	for _, answer := range body.Answers {
		question := questionMap[answer.ID]
		switch question.Type {
		case SingleSelection:
			fallthrough
		case TrueOrFalse:
			if len(answer.Answer) != 1 || answer.Answer[0] != question.AnswerOptions[0] {
				wrongQuestions = append(wrongQuestions, answer.ID)
				continue
			}
		case MultiSelection:
			sortedAnswer := make([]string, len(answer.Answer))
			copy(sortedAnswer, answer.Answer)
			sort.Strings(sortedAnswer)
			if !slices.Equal(sortedAnswer, question.AnswerOptions) {
				wrongQuestions = append(wrongQuestions, answer.ID)
				continue
			}
		}
	}

	if len(wrongQuestions) > 0 {
		return c.JSON(SubmitResponse{
			Correct:          false,
			Message:          "wrong answer",
			WrongQuestionIDs: wrongQuestions,
		})
	}

	err = DB.Model(&user).Update("has_answered_questions", true).Error
	if err != nil {
		return
	}

	accessToken, refreshToken, err := user.CreateJWTToken()

	return c.JSON(SubmitResponse{
		Correct: true,
		Message: "answer correct, register success",
		TokenResponse: TokenResponse{
			Access:  accessToken,
			Refresh: refreshToken,
		},
	})
}

// ReloadQuestions godoc
// @summary Reload questions
// @description Reload questions, admin only
// @tags question
// @produce json
// @router /register/questions/_reload [post]
// @success 204
// @failure 403 {object} common.HttpError "forbidden"
// @failure 500 {string} common.HttpError "internal server error"
func ReloadQuestions(c *fiber.Ctx) (err error) {
	userID, err := common.GetUserID(c)
	if err != nil {
		return
	}

	if !IsAdmin(userID) {
		return common.Forbidden("only admin can reload questions")
	}

	err = InitQuestions()
	if err != nil {
		return common.InternalServerError("reload question failed: " + err.Error())
	}

	return c.SendStatus(fiber.StatusNoContent)
}

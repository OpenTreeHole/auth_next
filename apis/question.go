package apis

import (
	"encoding/json"
	"fmt"
	"sort"

	. "auth_next/models"

	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/rand"
	"golang.org/x/exp/slices"
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

	_, err = LoadUserFromDB(userID)
	if err != nil {
		return
	}

	//if user.HasAnsweredQuestions {
	//	return common.BadRequest("you have answered questions")
	//}

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
		// questions                 = questionConfig.Questions
		// number                    = questionConfig.Spec.NumberOfQuestions
		requiredQuestions         = questionConfig.RequiredQuestions
		optionalQuestions         = questionConfig.OptionalQuestions
		campusQuestions           = questionConfig.CampusQuestions
		numberOfOptionalQuestions = questionConfig.Spec.NumberOfOptionalQuestions
		numberOfCampusQuestions   = questionConfig.Spec.NumberOfCampusQuestions
		inOrder                   = questionConfig.Spec.InOrder
	)

	number := len(requiredQuestions)
	if numberOfOptionalQuestions == -1 {
		number += len(optionalQuestions)
	} else if numberOfOptionalQuestions >= 0 {
		number += numberOfOptionalQuestions
	} else {
		return common.InternalServerError("[retrieve questions]: number of optional questions invalid")
	}
	if numberOfCampusQuestions == -1 {
		number += len(campusQuestions)
	} else if numberOfCampusQuestions >= 0 {
		number += numberOfCampusQuestions
	} else {
		return common.InternalServerError("[retrieve questions]: number of campus questions invalid")
	}

	var questionsResponse = QuestionConfig{
		Version: version,
		Spec: QuestionSpec{
			NumberOfOptionalQuestions: numberOfOptionalQuestions,
			NumberOfCampusQuestions:   numberOfCampusQuestions,
			NumberOfQuestions:         number,
			InOrder:                   inOrder,
		},
	}

	questionsResponse.Questions = make([]Question, number)
	tmpQuestions := make([]*Question, 0, number)

	if number == 0 {
		return common.InternalServerError("[retrieve questions]: number of questions too small")
	}

	copy(tmpQuestions, requiredQuestions)

	// for i, question := range requiredQuestions {
	// 	tmpQuestions[i] = question
	// 	// questionsResponse.Questions[i] = *question
	// }

	// questionConfig.Questions = append(questionConfig.Questions, optionalQuestions...)
	if numberOfOptionalQuestions == -1 {
		// send all opntional questions
		tmpQuestions = append(tmpQuestions, optionalQuestions...)
	} else if numberOfOptionalQuestions > 0 {
		// shuffle optional questions
		chosenOptionalQuestions := make([]*Question, len(optionalQuestions))
		copy(chosenOptionalQuestions, optionalQuestions)
		rand.Shuffle(len(chosenOptionalQuestions), func(i, j int) {
			chosenOptionalQuestions[i], chosenOptionalQuestions[j] = chosenOptionalQuestions[j], chosenOptionalQuestions[i]
		})

		tmpQuestions = append(tmpQuestions, chosenOptionalQuestions[:numberOfOptionalQuestions]...)
	}

	if numberOfCampusQuestions == -1 {
		// send all campus questions
		tmpQuestions = append(tmpQuestions, campusQuestions...)
	} else if numberOfCampusQuestions > 0 {
		// shuffle campus questions
		chosenCampusQuestions := make([]*Question, len(campusQuestions))
		copy(chosenCampusQuestions, campusQuestions)
		rand.Shuffle(len(chosenCampusQuestions), func(i, j int) {
			chosenCampusQuestions[i], chosenCampusQuestions[j] = chosenCampusQuestions[j], chosenCampusQuestions[i]
		})

		tmpQuestions = append(tmpQuestions, chosenCampusQuestions[:numberOfCampusQuestions]...)
	}

	if !inOrder {
		rand.Shuffle(len(tmpQuestions), func(i, j int) {
			tmpQuestions[i], tmpQuestions[j] = tmpQuestions[j], tmpQuestions[i]
		})
	} else {
		sort.Slice(tmpQuestions, func(i, j int) bool {
			return tmpQuestions[i].ID < tmpQuestions[j].ID
		})
	}

	for i, question := range tmpQuestions {
		questionsResponse.Questions[i] = *question
	}

	jsonQuestions, _ := json.Marshal(questionsResponse)
	log.Debug().Msgf("questionsResponse: %s", string(jsonQuestions))

	// shuffle options
	for i := range questionsResponse.Questions {
		options := questionsResponse.Questions[i].Options // copy slice pointer only
		rand.Shuffle(len(options), func(j, k int) {
			options[j], options[k] = options[k], options[j]
		})
	}

	// clear analysis and answer
	for i := range questionsResponse.Questions {
		if questionsResponse.Questions[i].Group == "campus" {
			questionsResponse.Questions[i].Group = "optional"
		}
		questionsResponse.Questions[i].Analysis = ""
		questionsResponse.Questions[i].Answer = nil
		questionsResponse.Questions[i].Option = questionsResponse.Questions[i].Options
	}

	jsonQuestions, _ = json.Marshal(questionsResponse)
	log.Debug().Msgf("questionsResponse: %s", string(jsonQuestions))

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

	//if user.HasAnsweredQuestions {
	//	return common.BadRequest("you have answered questions")
	//}

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
	)

	number := len(requiredQuestions) + questionConfig.Spec.NumberOfOptionalQuestions + questionConfig.Spec.NumberOfCampusQuestions

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

	user.HasAnsweredQuestions = true
	err = DB.Model(&user).Update("has_answered_questions", true).Error
	if err != nil {
		return
	}

	accessToken, refreshToken, err := user.CreateJWTToken()
	if err != nil {
		return
	}

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

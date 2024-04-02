package apis

import (
	"errors"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/goccy/go-json"
	"github.com/opentreehole/go-common"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"

	"auth_next/config"
	"auth_next/models"
	"auth_next/utils/shamir"
)

var GlobalUploadShamirStatus struct {
	sync.Mutex
	ShamirStatusResponse
}

func Init() {
	InitShamirStatus()
	InitUserSharesStatus()

	if config.Config.EnableRegisterQuestions {
		err := InitQuestions()
		if err != nil {
			log.Fatal().Err(err).Msg("init questions failed")
		}
	}
}

func InitShamirStatus() {
	GlobalUploadShamirStatus.ShamirStatusResponse = ShamirStatusResponse{
		UploadedShares:              make(map[int]shamir.Shares, 0),
		CurrentPublicKeys:           models.ShamirPublicKeys,
		UploadedSharesIdentityNames: make([]string, 0, 7),
		NewPublicKeys:               make([]models.ShamirPublicKey, 0, 7),
	}
}

var GlobalQuestionConfig struct {
	sync.RWMutex
	Questions      map[int]QuestionConfig
	CurrentVersion int
}

func InitQuestions() error {
	// load questions from ./data/questions directory
	dir, err := os.ReadDir("./data/questions")
	if err != nil {
		return err
	}

	var newQuestions = make(map[int]QuestionConfig, len(dir))
	var newQuestionCurrentVersion = 0

LOAD_FILES:
	for _, file := range dir {
		if file.IsDir() {
			continue
		}

		var questionConfig QuestionConfig

		filename := file.Name()
		var fileType string
		if strings.HasSuffix(filename, ".json") {
			fileType = "json"
		} else if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
			fileType = "yaml"
		} else {
			continue
		}

		// read file
		data, err := os.ReadFile("./data/questions/" + file.Name())
		if err != nil {
			log.Err(err).Str("filename", file.Name()).Msg("read question file failed")
			continue
		}

		// unmarshal
		switch fileType {
		case "json":
			err = json.Unmarshal(data, &questionConfig)
		case "yaml":
			err = yaml.Unmarshal(data, &questionConfig)
		default:
			continue
		}
		if err != nil {
			log.Err(err).Str("filename", file.Name()).Msg("unmarshal question file failed")
			continue
		}

		// validate
		err = common.ValidateStruct(&questionConfig)
		if err != nil {
			log.Err(err).Str("filename", file.Name()).Msg("validate question file failed")
			continue
		}

		if _, ok := newQuestions[questionConfig.Version]; ok {
			log.Warn().Str("filename", file.Name()).Msg("duplicate version")
			continue
		}

		// parse required questions and optional questions
		for i := range questionConfig.Questions {
			currentQuestion := &questionConfig.Questions[i]
			if currentQuestion.Group == "required" {
				questionConfig.RequiredQuestions = append(questionConfig.RequiredQuestions, currentQuestion)
			} else {
				questionConfig.OptionalQuestions = append(questionConfig.OptionalQuestions, currentQuestion)
			}
		}

		if questionConfig.Spec.NumberOfQuestions > 0 {
			if questionConfig.Spec.NumberOfQuestions < len(questionConfig.RequiredQuestions) {
				log.Warn().
					Str("filename", file.Name()).
					Int("number_of_questions", questionConfig.Spec.NumberOfQuestions).
					Int("number_of_required_questions", len(questionConfig.RequiredQuestions)).
					Msg("expected number of questions is less than number of required questions")
				continue LOAD_FILES
			}
			if questionConfig.Spec.NumberOfQuestions > len(questionConfig.Questions) {
				log.Warn().
					Str("filename", file.Name()).
					Int("number_of_questions", questionConfig.Spec.NumberOfQuestions).
					Int("number_of_questions", len(questionConfig.Questions)).
					Msg("expected number of questions is greater than number of questions")
				continue LOAD_FILES
			}
		}

		valid := true
		for i := range questionConfig.Questions {
			currentQuestion := &questionConfig.Questions[i]

			// set question id
			currentQuestion.ID = i + 1

			// validate question
			switch currentQuestion.Type {
			case SingleSelection:
				if len(currentQuestion.Answer) != 1 {
					log.Warn().
						Str("filename", file.Name()).
						Str("question", currentQuestion.Question).
						Int("id", currentQuestion.ID).
						Msg("single selection question must have one answer")
					valid = false
					continue
				}
				currentQuestion.AnswerOptions = append(currentQuestion.AnswerOptions, currentQuestion.Options[currentQuestion.Answer[0]])
			case TrueOrFalse:
				if len(currentQuestion.Answer) != 1 || (currentQuestion.Answer[0] != 0 && currentQuestion.Answer[0] != 1) {
					log.Warn().
						Str("filename", file.Name()).
						Str("question", currentQuestion.Question).
						Int("id", currentQuestion.ID).
						Msg("true or false question must have one answer and must be true or false")
					valid = false
					continue
				}
				currentQuestion.AnswerOptions = append(currentQuestion.AnswerOptions,
					currentQuestion.Options[currentQuestion.Answer[0]])
			case MultiSelection:
				if len(currentQuestion.Answer) < 1 {
					log.Warn().
						Str("filename", file.Name()).
						Str("question", currentQuestion.Question).
						Int("id", currentQuestion.ID).
						Msg("multi selection question must have at least one answer")
					valid = false
					continue
				}
				currentQuestion.AnswerOptions = make([]string, 0, len(currentQuestion.Answer))
				for _, index := range currentQuestion.Answer {
					if index < len(currentQuestion.Options) {
						currentQuestion.AnswerOptions = append(currentQuestion.AnswerOptions, currentQuestion.Options[index])
					}
				}
				sort.Strings(currentQuestion.AnswerOptions)
			}
		}
		if !valid {
			continue
		}

		newQuestions[questionConfig.Version] = questionConfig
	}

	if len(newQuestions) == 0 {
		return errors.New("no valid questions found")
	}

	for version := range newQuestions {
		if version > newQuestionCurrentVersion {
			newQuestionCurrentVersion = version
		}
	}

	GlobalQuestionConfig.Lock()
	GlobalQuestionConfig.Questions = newQuestions
	GlobalQuestionConfig.CurrentVersion = newQuestionCurrentVersion
	GlobalQuestionConfig.Unlock()

	return nil
}

var GlobalUserSharesStatus struct {
	sync.Mutex
	ShamirUsersSharesResponse
}

func InitUserSharesStatus() {
	GlobalUserSharesStatus.ShamirUsersSharesResponse = ShamirUsersSharesResponse{
		UploadedShares:              make(map[int]shamir.Shares, 0),
		UploadedSharesIdentityNames: make(map[int][]string, 0),
		ShamirUploadReady:           make(map[int]bool, 0),
	}
}

package apis

import (
	"fmt"
	"strconv"
	"strings"

	"auth_next/models"
	"auth_next/utils/shamir"
)

/* account */

type EmailModel struct {
	// email in email blacklist
	Email string `json:"email" query:"email" validate:"isValidEmail"`
}

type LoginRequest struct {
	EmailModel
	Password string `json:"password" minLength:"8"`
}

type TokenResponse struct {
	Access  string `json:"access,omitempty"`
	Refresh string `json:"refresh,omitempty"`
	Message string `json:"message,omitempty"`
}

type RegisterRequest struct {
	LoginRequest
	Verification VerificationType `json:"verification" swaggerType:"string"`
}

type RegisterInBatchRequest struct {
	Data []LoginRequest `json:"data"`
}

type VerificationType string

func (v *VerificationType) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	// Ignore null, like in the main JSON package.
	if s == "null" {
		return nil
	}

	number, err := strconv.Atoi(s)
	if err != nil {
		return err
	}

	*v = VerificationType(fmt.Sprintf("%06d", number))
	return nil
}

func (v *VerificationType) UnmarshalText(data []byte) error {
	s := strings.Trim(string(data), `"`)
	// Ignore null, like in the main JSON package.
	if s == "" {
		return nil
	}

	*v = VerificationType(s)
	return nil
}

type EmailVerifyResponse struct {
	Message    string `json:"message"`
	Registered bool   `json:"registered"`
	Scope      string `json:"scope" enums:"register,reset"`
}

type ApikeyRequest struct {
	EmailModel
	Apikey        string `json:"apikey" query:"apikey"`
	CheckRegister bool   `json:"check_register" query:"check_register" default:"false"` // if true, return whether registered
}

type ApikeyResponse struct {
	EmailVerifyResponse
	Code string `json:"code"`
}

/* Register Questions */

type QuestionType = string

const (
	SingleSelection QuestionType = "single-selection"
	TrueOrFalse     QuestionType = "true-or-false"
	MultiSelection  QuestionType = "multi-selection"
)

// Question 通用题目 schema.
// 题库中不需要设置 ID 信息，加载题库时由上到下自动设置题号
// 发送题目时去除 Answer 信息，需要有自动生成的 ID 信息
// 按照题库设置可选乱序出题
type Question struct {
	// 题目 ID，题库解析时自动生成，题库中不必填写，发送给客户端时必须包含
	ID int `json:"id,omitempty" yaml:"id,omitempty"`

	// 题目类型，单选、判断、多选
	Type QuestionType `json:"type" yaml:"type" validate:"oneof=single-selection true-or-false multi-selection"`

	// 题目分组，可选或必选
	Group string `json:"group" yaml:"group" validate:"oneof=optional required"`

	// 问题描述
	Question string `json:"question" yaml:"question" validate:"required"`

	// 答案描述，单选、判断、多选
	// 如果是单选题，则只有一个答案
	// 如果是多选题，则有一个或多个答案
	// 如果是判断题，则只有一个答案，且只能是 true 或者 false
	Answer []string `json:"answer,omitempty" yaml:"answer,omitempty" validate:"min=1"`

	// 选项描述，单选、判断、多选
	// 有一个或多个选项，如果是判断题，则选项只能是 true 或者 false
	// 如果 Answer 中的答案不在 Options 中，则会在解析时加到 Options 中
	Options []string `json:"options" yaml:"options"`

	// 题目解析，预留，可选
	Analysis string `json:"analysis,omitempty" yaml:"analysis,omitempty"`
}

// QuestionSpec 题库的发题、判题的规格 schema
type QuestionSpec struct {
	// 表示总的题目数量。
	// 发送题目时，题库中的必做题都会发送，可选题会根据题目数量随机发送。
	// 如果总的题目数量小于题库中的必做题数量，将会在解析时返回错误。
	// 如果设置为 0 或者不设置，则题库中的所有题目都会发送
	// 如果设置为 -1，则题库中的必做题都会发送，可选题不会发送
	NumberOfQuestions int `json:"number_of_questions" yaml:"number_of_questions"`

	// 表示是否由题目声明顺序由上到下顺序出题，默认为 false，即乱序出题
	InOrder bool `json:"in_order" yaml:"in_order"`
}

// QuestionConfig 题库配置文件 schema.
type QuestionConfig struct {
	// 表示题库的版本号，用于判题时判断对应的题库，保障题库的平滑更新，必须填写
	Version int `json:"version" yaml:"version" validate:"required,min=1"`

	// 题目列表
	Questions []Question `json:"questions" yaml:"questions"`

	// 出题规格
	Spec QuestionSpec `json:"spec" yaml:"spec"`

	// 辅助信息，不需要填写
	RequiredQuestions []*Question `json:"-" yaml:"-"`
	OptionalQuestions []*Question `json:"-" yaml:"-"`
}

// SubmitAnswer 提交的答案 schema.
// 可以与发送题目时 ID 顺序不一致，但是必须包含 ID 信息
type SubmitAnswer struct {
	// 题目 ID，用于判题，必须填写
	ID int `json:"id" yaml:"id" validate:"required"`

	// 答案描述，单选、判断、多选
	Answer []string `json:"answer" yaml:"answer" validate:"min=1"`
}

// SubmitRequest 提交的答案请求 schema.
// 将会根据题库版本号进行判题，如果答案的规格和题库不一致，将会返回错误
type SubmitRequest struct {
	// 表示题库的版本号，如果不填会使用最新的版本号判题，建议填写
	Version int `json:"version" yaml:"version"`

	// 答案列表
	Answers []SubmitAnswer `json:"answers" yaml:"answers" validate:"required,min=1,dive"`
}

type SubmitResponse struct {
	// 表示是否正确
	Correct bool `json:"correct"`

	// 消息提示
	Message string `json:"message,omitempty"`

	// 如果提交的答案不正确，返回错误的题目 ID
	WrongQuestionIDs []int `json:"wrong_question_ids,omitempty"`

	// 如果提交的答案全部正确，返回 Token
	TokenResponse `json:",inline"`
}

/* user account */

type ModifyUserRequest struct {
	Nickname *string `json:"nickname" validate:"omitempty,min=1"`
}

/* shamir */

type PGPMessageRequest struct {
	IdentityName string `json:"identity_name" query:"identity_name" validate:"required"`
}

type PGPMessageResponse struct {
	UserID     int    `json:"user_id"`
	PGPMessage string `json:"pgp_message" gorm:"column:key"`
}

type UserShare struct {
	UserID int          `json:"user_id"`
	Share  shamir.Share `json:"share" swaggerType:"string"`
}

type UploadSharesRequest struct {
	PGPMessageRequest
	Shares []UserShare `json:"shares" query:"shares"`
}

type UploadPublicKeyRequest struct {
	Data []string `json:"data" validate:"required,len=7"` // all standalone public keys
}

type IdentityNameResponse struct {
	IdentityNames []string `json:"identity_names"`
}

type ShamirStatusResponse struct {
	ShamirUpdateReady           bool                     `json:"shamir_update_ready"`
	ShamirUpdating              bool                     `json:"shamir_updating"`
	UploadedSharesIdentityNames []string                 `json:"uploaded_shares_identity_names"`
	UploadedShares              map[int]shamir.Shares    `json:"-"`
	CurrentPublicKeys           []models.ShamirPublicKey `json:"current_public_keys"`
	NewPublicKeys               []models.ShamirPublicKey `json:"new_public_keys"`
	NowUserID                   int                      `json:"now_user_id,omitempty"`
	FailMessage                 string                   `json:"fail_message,omitempty"`
	WarningMessage              string                   `json:"warning_message,omitempty"`
}

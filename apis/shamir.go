package apis

// apis in this page won't check permission, and should be terminated by api gateway in production environment

import (
	"auth_next/config"
	. "auth_next/models"
	"auth_next/utils"
	"auth_next/utils/shamir"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"runtime"
	"strings"
)

// GetPGPMessageByUserID godoc
//
// @Summary get shamir PGP message
// @Tags shamir
// @Produce json
// @Router /shamir/{user_id} [get]
// @Param user_id path int true "Target UserID"
// @Param identity_name query PGPMessageRequest true "recipient uid"
// @Success 200 {object} PGPMessageResponse
// @Failure 400 {object} common.MessageResponse
// @Failure 500 {object} common.MessageResponse
func GetPGPMessageByUserID(c *fiber.Ctx) error {
	// get identity
	var query PGPMessageRequest
	err := common.ValidateQuery(c, &query)
	if err != nil {
		return err
	}

	// get target user id
	targetUserID, err := c.ParamsInt("id", 0)
	if err != nil {
		return err
	}
	if targetUserID <= 0 {
		return errors.New("user_id at least 1")
	}

	// get related pgp message key
	var key string
	result := DB.Model(&ShamirEmail{}).Select("key").
		Where("encrypted_by = ? AND user_id = ?", query.IdentityName, targetUserID).
		Take(&key)
	// DB.Take raise error when take nothing
	if result.Error != nil {
		return result.Error
	}

	// log
	log.Printf("admin try to get user %v shamir pgp message with identity %v\n",
		targetUserID, query.IdentityName)

	return c.JSON(PGPMessageResponse{
		UserID:     targetUserID,
		PGPMessage: key,
	})
}

// ListPGPMessages godoc
//
// @Summary list related shamir PGP messages
// @Tags shamir
// @Produce json
// @Router /shamir [get]
// @Param identity_name query string true "recipient uid"
// @Success 200 {array} PGPMessageResponse
// @Failure 400 {object} common.MessageResponse
// @Failure 500 {object} common.MessageResponse
func ListPGPMessages(c *fiber.Ctx) error {
	// get identity
	var query PGPMessageRequest
	err := common.ValidateQuery(c, &query)
	if err != nil {
		return err
	}

	// list pgp messages
	messages := make([]PGPMessageResponse, 0, 10)
	result := DB.Table("shamir_email").Order("user_id asc").
		Where("encrypted_by = ?", query.IdentityName).
		Find(&messages)
	if result.Error != nil {
		return result.Error
	}
	if len(messages) == 0 {
		return c.Status(404).JSON(common.Message("获取Shamir信息失败"))
	}

	// log
	log.Printf("identity %s lists all pgp messages\n", query.IdentityName)

	return c.JSON(messages)
}

// UploadAllShares godoc
//
// @Summary upload all shares of all users, cached
// @Tags shamir
// @Produce json
// @Router /shamir/shares [post]
// @Param shares body UploadSharesRequest true "shares"
// @Success 200 {object} common.MessageResponse{data=IdentityNameResponse}
// @Success 201 {object} common.MessageResponse{data=IdentityNameResponse}
// @Failure 400 {object} common.MessageResponse
// @Failure 500 {object} common.MessageResponse
func UploadAllShares(c *fiber.Ctx) error {
	// get shares
	var body UploadSharesRequest
	err := common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	// lock
	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	if status.ShamirUpdating {
		return common.BadRequest("正在重新加解密，请不要上传")
	}

	if utils.InUnorderedSlice(status.UploadedSharesIdentityNames, body.IdentityName) {
		return common.BadRequest("您已经上传过，请不要重复上传")
	}
	status.UploadedSharesIdentityNames = append(status.UploadedSharesIdentityNames, body.IdentityName)

	// save shares
	for _, userShare := range body.Shares {
		userID := userShare.UserID
		// also correct if status.UploadedShares[userID] = nil
		status.UploadedShares[userID] = append(status.UploadedShares[userID], userShare.Share)
	}

	if len(status.UploadedSharesIdentityNames) >= 4 && len(status.NewPublicKeys) == 7 {
		status.ShamirUpdateReady = true
	}

	return c.JSON(common.MessageResponse{
		Message: "上传成功",
		Data: Map{
			"identity_name":      body.IdentityName,
			"now_updated_shares": GlobalUploadShamirStatus.UploadedSharesIdentityNames,
		},
	})
}

// UploadPublicKey godoc
//
// @Summary upload all PGP PublicKeys for encryption, admin only
// @Tags shamir
// @Produce json
// @Router /shamir/key [post]
// @Param public_keys body UploadPublicKeyRequest true "public keys"
// @Success 200 {array} common.MessageResponse{data=IdentityNameResponse}
// @Failure 400 {object} common.MessageResponse
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func UploadPublicKey(c *fiber.Ctx) error {
	var body UploadPublicKeyRequest
	err := common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	// save public keys
	status.NewPublicKeys = nil
	for i, armoredPublicKey := range body.Data {
		// try parse
		publicKey, err := crypto.NewKeyFromArmored(armoredPublicKey)
		if err != nil {
			return common.BadRequest(fmt.Sprintf("load public key error: %v\n", armoredPublicKey))
		}
		publicKeyRing, err := crypto.NewKeyRing(publicKey)
		if err != nil {
			return common.BadRequest(fmt.Sprintf("load public key error: %v\n", armoredPublicKey))
		}

		// save new public keys with assigned id, for save to database
		status.NewPublicKeys = append(status.NewPublicKeys, ShamirPublicKey{
			ID:               i + 1,
			IdentityName:     publicKey.GetEntity().PrimaryIdentity().Name,
			ArmoredPublicKey: armoredPublicKey,
			PublicKey:        publicKeyRing,
		})
	}

	if len(status.UploadedSharesIdentityNames) >= 4 && len(status.NewPublicKeys) == 7 {
		status.ShamirUpdateReady = true
	}

	return c.JSON(common.MessageResponse{
		Message: "上传公钥成功",
		Data:    &status.ShamirStatusResponse,
	})
}

// GetShamirStatus godoc
//
// @Summary get shamir info
// @Tags shamir
// @Produce json
// @Router /shamir/status [get]
// @Success 200 {object} ShamirStatusResponse
// @Failure 400 {object} common.MessageResponse
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func GetShamirStatus(c *fiber.Ctx) error {
	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()

	return c.JSON(GlobalUploadShamirStatus.ShamirStatusResponse)
}

// UpdateShamir godoc
//
// @Summary trigger for updating shamir
// @Tags shamir
// @Produce json
// @Router /shamir/update [post]
// @Success 200 {object} common.MessageResponse
// @Failure 400 {object} common.MessageResponse
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func UpdateShamir(c *fiber.Ctx) error {
	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	if status.ShamirUpdating {
		return common.BadRequest("正在重新加解密，请不要重复触发")
	}
	if !status.ShamirUpdateReady {
		if len(status.UploadedSharesIdentityNames) < 4 {
			return common.BadRequest("坐标点数量不够，无法解密")
		} else if len(status.NewPublicKeys) < 7 {
			return common.BadRequest("公钥数量不够，无法重新加密")
		} else {
			return common.BadRequest("无法解密")
		}
	}

	// trigger update
	go updateShamir()
	return c.JSON(common.Message("触发成功，正在尝试更新shamir信息，请访问/shamir/status获取更多信息"))
}

// RefreshShamir godoc
//
// @Summary trigger for refresh uploaded shares
// @Tags shamir
// @Router /shamir/refresh [put]
// @Success 204
// @failure 500 {object} common.MessageResponse
func RefreshShamir(c *fiber.Ctx) error {
	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	if status.ShamirUpdating {
		return common.BadRequest("正在重新加解密，请不要触发刷新")
	}

	status.UploadedSharesIdentityNames = []string{}
	status.UploadedShares = make(map[int]shamir.Shares, 0)

	status.ShamirUpdateReady = false
	status.ShamirUpdating = false

	return c.SendStatus(204)
}

// only background running in goroutine
func updateShamir() {
	var err error
	const taskScope = "shamir update"

	defer func() {
		panicErr := recover()
		if panicErr != nil {
			GlobalUploadShamirStatus.Lock()
			defer GlobalUploadShamirStatus.Unlock()
			status := &GlobalUploadShamirStatus

			status.FailMessage = fmt.Sprintf("recover from panic: %v", panicErr)
		}
	}()

	// prepare
	GlobalUploadShamirStatus.Lock()

	// shamir updating status
	GlobalUploadShamirStatus.ShamirUpdating = true

	// backup old public keys
	oldShamirPublicKey := ShamirPublicKeys

	// copy new public keys
	ShamirPublicKeys = GlobalUploadShamirStatus.NewPublicKeys
	GlobalUploadShamirStatus.CurrentPublicKeys = ShamirPublicKeys

	// all the shares for decrypt
	allShares := GlobalUploadShamirStatus.UploadedShares

	if len(allShares) == 0 {
		log.Error().Str("scope", taskScope).Msg("no shares uploaded")
		GlobalUploadShamirStatus.Unlock()
		return
	}

	// get all userID
	userIDs := make([]int, 0, len(allShares))
	for userID := range allShares {
		userIDs = append(userIDs, userID)
	}
	slices.Sort(userIDs)

	GlobalUploadShamirStatus.Unlock()

	var warningMessage strings.Builder

	const shamirTableName = "shamir_email"

	err = DB.Session(&gorm.Session{
		Logger:            DB.Logger.LogMode(logger.Warn),
		NewDB:             true,
		AllowGlobalUpdate: true,
		CreateBatchSize:   1000,
	}).Transaction(func(tx *gorm.DB) error {

		// concurrently compute
		taskChan := make(chan func(), 100)
		errChan := make(chan error)
		warningMessageChan := make(chan string, 1000)
		shamirEmailResultChan := make(chan []ShamirEmail, 100)
		defer func() {
			close(taskChan)
			close(errChan)
			close(warningMessageChan)
			close(shamirEmailResultChan)
		}()

		shamirEmails := make([]ShamirEmail, 0, len(ShamirPublicKeys)*len(userIDs))

		// task executor
		for i := 0; i < runtime.NumCPU(); i++ {
			go func() {
				for task := range taskChan {
					task()
				}
			}()
		}

		// task sender
		go func() {

			// main loop
			for _, userID := range userIDs {

				userID := userID
				// get shares
				shares := allShares[userID]
				if len(shares) < 4 {
					warningMessageChan <- fmt.Sprintf("user %v don't have enough shares\n", userID)
					continue
				}

				taskChan <- func() {

					// decrypt email
					email := shamir.Decrypt(shares)
					if !utils.ValidateEmail(email) {
						if !utils.IsEmail(email) {
							// decrypt error
							errChan <- fmt.Errorf("[email decrypt error] invalid email, user_id = %d, email: %v", userID, email)
							return
						} else {
							// filter invalid emails
							warningMessageChan <- fmt.Sprintf("user %v don't have valid email: %v\n", userID, email)
							return
						}
					}

					// generate shamir emails
					var innerShamirEmails []ShamirEmail
					innerShamirEmails, err = GenerateShamirEmails(userID, email)
					if err != nil {
						errChan <- err
						return
					}

					shamirEmailResultChan <- innerShamirEmails
				}
			}
		}()

		// receive task results
		taskCount := 0
		for range userIDs {
			select {
			case err = <-errChan:
				return err
			case innerWarningMessage := <-warningMessageChan:
				warningMessage.WriteString(innerWarningMessage)
			case innerShamirEmails := <-shamirEmailResultChan:
				shamirEmails = append(shamirEmails, innerShamirEmails...)
			}
			taskCount++
			if taskCount%1000 == 0 {
				log.Info().Str("scope", taskScope).Msgf("processed %v users", taskCount)
			}
			GlobalUploadShamirStatus.Lock()
			GlobalUploadShamirStatus.NowUserID = taskCount
			GlobalUploadShamirStatus.Unlock()
		}

		// delete old table
		if tx.Dialector.Name() == "sqlite" {
			//goland:noinspection SqlWithoutWhere
			err = tx.Exec(`DELETE FROM ` + shamirTableName).Error
		} else {
			err = tx.Exec(`TRUNCATE ` + shamirTableName).Error
		}
		if err != nil {
			return err
		}

		// insert new shamir emails
		err = tx.Create(shamirEmails).Error
		if err != nil {
			return err
		}

		// save new public keys
		err = tx.Save(ShamirPublicKeys).Error
		if err != nil {
			return err
		}

		return nil
	})

	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	status.ShamirUpdating = false
	status.ShamirUpdateReady = false
	status.WarningMessage = warningMessage.String()
	for userID := range status.UploadedShares {
		delete(status.UploadedShares, userID)
	}
	status.UploadedSharesIdentityNames = []string{}
	status.NewPublicKeys = []ShamirPublicKey{}
	status.NowUserID = 0

	var subject string
	var content []byte

	if err != nil {
		// rollback
		status.FailMessage = err.Error()
		status.NewPublicKeys = ShamirPublicKeys
		status.CurrentPublicKeys = oldShamirPublicKey
		ShamirPublicKeys = oldShamirPublicKey

		subject = "shamir update failed"
	} else {
		subject = "shamir update success"
	}

	content, _ = json.Marshal(&status)

	// send email to update
	err = utils.SendEmail(subject, string(content), []string{config.Config.EmailDev})
	if err != nil {
		log.Warn().Err(err).Str("scope", taskScope).Str("subject", subject).Msg("sending email failed")
	}

	log.Info().Str("scope", taskScope).Msg("updateShamir function finished")
}

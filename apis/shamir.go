package apis

import (
	"auth_next/config"
	"auth_next/models"
	"auth_next/utils"
	"auth_next/utils/shamir"
	"encoding/json"
	"fmt"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/gofiber/fiber/v2"
	"golang.org/x/exp/slices"
	"gorm.io/gorm"
	"log"
	"strings"
)

// GetPGPMessageByUserID godoc
//
//	@Summary	get shamir PGP message
//	@Tags		shamir
//	@Produce	json
//	@Router		/shamir/{user_id} [get]
//	@Param		user_id			path		int					true	"Target UserID"
//	@Param		identity_name	query		PGPMessageRequest	true	"recipient uid"
//	@Success	200				{object}	PGPMessageResponse
//	@Failure	400				{object}	utils.MessageResponse
//	@Failure	500				{object}	utils.MessageResponse
func GetPGPMessageByUserID(c *fiber.Ctx) error {
	// get identity
	var query PGPMessageRequest
	err := utils.ValidateQuery(c, &query)
	if err != nil {
		return err
	}

	// get target user id
	targetUserID, err := c.ParamsInt("id")
	if err != nil {
		return err
	}

	// get related pgp message key
	var key string
	result := models.DB.Table("shamir_email").Select("key").
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
//	@Summary	list related shamir PGP messages
//	@Tags		shamir
//	@Produce	json
//	@Router		/shamir [get]
//	@Param		identity_name	query		string	true	"recipient uid"
//	@Success	200				{array}		PGPMessageResponse
//	@Failure	400				{object}	utils.MessageResponse
//	@Failure	500				{object}	utils.MessageResponse
func ListPGPMessages(c *fiber.Ctx) error {
	// get identity
	var query PGPMessageRequest
	err := utils.ValidateQuery(c, &query)
	if err != nil {
		return err
	}

	// list pgp messages
	messages := make([]PGPMessageResponse, 0, 10)
	result := models.DB.Table("shamir_email").Order("user_id asc").
		Where("encrypted_by = ?", query.IdentityName).
		Find(&messages)
	if result.Error != nil {
		return result.Error
	}
	if len(messages) == 0 {
		return c.Status(404).JSON(utils.Message("获取Shamir信息失败"))
	}

	// log
	log.Printf("identity %s lists all pgp messages\n", query.IdentityName)

	return c.JSON(messages)
}

// UploadAllShares godoc
//
//	@Summary	upload all shares of all users, cached
//	@Tags		shamir
//	@Produce	json
//	@Router		/shamir/shares [post]
//	@Param		shares	body		UploadSharesRequest	true	"shares"
//	@Success	200		{object}	utils.MessageResponse{data=IdentityNameResponse}
//	@Success	201		{object}	utils.MessageResponse{data=IdentityNameResponse}
//	@Failure	400		{object}	utils.MessageResponse
//	@Failure	500		{object}	utils.MessageResponse
func UploadAllShares(c *fiber.Ctx) error {
	// get shares
	var body UploadSharesRequest
	err := utils.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	// lock
	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	if status.ShamirUpdating {
		return utils.BadRequest("正在重新加解密，请不要上传")
	}

	if utils.InUnorderedSlice(status.UploadedSharesIdentityNames, body.IdentityName) {
		return utils.BadRequest("您已经上传过，请不要重复上传")
	}
	status.UploadedSharesIdentityNames = append(status.UploadedSharesIdentityNames, body.IdentityName)

	// save shares
	for _, userShare := range body.Shares {
		userID := userShare.UserID
		// also correct if status.UploadedShares[userID] = nil
		status.UploadedShares[userID] = append(status.UploadedShares[userID], userShare.Share)
	}

	if len(status.UploadedSharesIdentityNames) >= 4 {
		status.ShamirUpdateReady = true
	}

	return c.JSON(utils.MessageResponse{
		Message: "上传成功",
		Data: models.Map{
			"identity_name":      body.IdentityName,
			"now_updated_shares": GlobalUploadShamirStatus.UploadedSharesIdentityNames,
		},
	})
}

// UploadPublicKey godoc
//
//	@Summary	upload all PGP PublicKeys for encryption, admin only
//	@Tags		shamir
//	@Produce	json
//	@Router		/shamir/key [post]
//	@Param		public_keys	body		UploadPublicKeyRequest	true	"public keys"
//	@Success	200			{array}		utils.MessageResponse{data=IdentityNameResponse}
//	@Failure	400			{object}	utils.MessageResponse
//	@Failure	403			{object}	utils.MessageResponse	"非管理员"
//	@Failure	500			{object}	utils.MessageResponse
func UploadPublicKey(c *fiber.Ctx) error {
	var body UploadPublicKeyRequest
	err := utils.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	// get request user id
	requestUserID, err := models.GetUserID(c)
	if err != nil {
		return err
	}
	if !models.IsAdmin(requestUserID) {
		return utils.Forbidden("你没有权限上传新的公钥")
	}
	if len(body.Data) != 7 {
		return utils.BadRequest("公钥数量不足")
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
			return utils.BadRequest(fmt.Sprintf("load public key error: %v\n", armoredPublicKey))
		}
		publicKeyRing, err := crypto.NewKeyRing(publicKey)
		if err != nil {
			return utils.BadRequest(fmt.Sprintf("load public key error: %v\n", armoredPublicKey))
		}

		// save new public keys with assigned id, for save to database
		status.NewPublicKeys = append(status.NewPublicKeys, models.ShamirPublicKey{
			ID:               i + 1,
			IdentityName:     publicKey.GetEntity().PrimaryIdentity().Name,
			ArmoredPublicKey: armoredPublicKey,
			PublicKey:        publicKeyRing,
		})
	}
	return c.JSON(utils.MessageResponse{
		Message: "上传公钥成功",
		Data:    &status.ShamirStatusResponse,
	})
}

// GetShamirStatus godoc
//
//	@Summary	get shamir info
//	@Tags		shamir
//	@Produce	json
//	@Router		/shamir/status [get]
//	@Success	200	{object}	ShamirStatusResponse
//	@Failure	400	{object}	utils.MessageResponse
//	@Failure	403	{object}	utils.MessageResponse	"非管理员"
//	@Failure	500	{object}	utils.MessageResponse
func GetShamirStatus(c *fiber.Ctx) error {
	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()

	return c.JSON(GlobalUploadShamirStatus.ShamirStatusResponse)
}

// UpdateShamir godoc
//
//	@Summary	trigger for updating shamir
//	@Tags		shamir
//	@Produce	json
//	@Router		/shamir/update [post]
//	@Success	200	{object}	utils.MessageResponse
//	@Failure	400	{object}	utils.MessageResponse
//	@Failure	403	{object}	utils.MessageResponse	"非管理员"
//	@Failure	500	{object}	utils.MessageResponse
func UpdateShamir(c *fiber.Ctx) error {
	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	if status.ShamirUpdating {
		return utils.BadRequest("正在重新加解密，请不要重复触发")
	}
	if !status.ShamirUpdateReady {
		return utils.BadRequest("坐标点数量不够，无法解密")
	}
	if len(status.NewPublicKeys) < 7 {
		return utils.BadRequest("公钥数量不够，无法重新加密")
	}

	// trigger update
	go updateShamir()
	return c.JSON(utils.Message("触发成功，正在尝试更新shamir信息，请访问/shamir/status获取更多信息"))
}

// only background running in goroutine
func updateShamir() {
	defer func() {
		if err := recover(); err != nil {
			GlobalUploadShamirStatus.Lock()
			defer GlobalUploadShamirStatus.Unlock()
			status := &GlobalUploadShamirStatus

			status.FailMessage = fmt.Sprintf("recover from panic: %v", err)
		}
	}()
	// prepare
	GlobalUploadShamirStatus.Lock()

	// shamir updating status
	GlobalUploadShamirStatus.ShamirUpdating = true

	// backup old public keys
	oldShamirPublicKey := models.ShamirPublicKeys

	// copy new public keys
	models.ShamirPublicKeys = GlobalUploadShamirStatus.NewPublicKeys
	GlobalUploadShamirStatus.CurrentPublicKeys = models.ShamirPublicKeys

	// all the shares for decrypt
	allShares := GlobalUploadShamirStatus.UploadedShares

	// get all userID
	userIDs := make([]int, 0, len(allShares))
	for userID := range allShares {
		userIDs = append(userIDs, userID)
	}
	slices.Sort(userIDs)

	GlobalUploadShamirStatus.Unlock()

	var warningMessage strings.Builder

	const (
		shamirTableName       = "shamir_email"
		backupShamirTableName = "shamir_email_backup"
	)

	err := models.DB.Transaction(func(tx *gorm.DB) error {

		// backup old table

		if tx.Migrator().HasTable(backupShamirTableName) {
			err := tx.Migrator().DropTable(backupShamirTableName)
			if err != nil {
				return err
			}
		}
		if tx.Migrator().HasTable(shamirTableName) {
			err := tx.Migrator().RenameTable(shamirTableName, backupShamirTableName)
			if err != nil {
				return err
			}
		}
		// create new table
		err := tx.AutoMigrate(models.ShamirEmail{})
		if err != nil {
			return err
		}

		// main loop
		for _, userID := range userIDs {
			// update userID status
			GlobalUploadShamirStatus.Lock()
			GlobalUploadShamirStatus.NowUserID = userID
			GlobalUploadShamirStatus.Unlock()

			// get shares
			shares := allShares[userID]
			if len(shares) < 4 {
				warningMessage.WriteString(fmt.Sprintf("user %v don't have enough shares\n", userID))
				continue
			}

			// decrypt email
			email := shamir.Decrypt(shares)
			if !utils.ValidateEmail(email) {
				if !utils.IsEmail(email) {
					// decrypt error
					return fmt.Errorf("[email decrypt error] invalid email, user_id = %d, email: %v", userID, email)
				} else {
					// filter invalid emails
					warningMessage.WriteString(fmt.Sprintf("user %v don't have valid email: %v\n", userID, email))
				}
			}

			// get new shares
			newShares, err := shamir.Encrypt(email, 7, 4)
			if err != nil {
				return err
			}

			// store to database
			err = models.CreateShamirEmails(tx, userID, newShares)
			if err != nil {
				return err
			}
		}

		// drop table shamir_email_backup
		if tx.Migrator().HasTable(backupShamirTableName) {
			err := tx.Migrator().DropTable(backupShamirTableName)
			if err != nil {
				return err
			}
		}

		// save new public keys
		return tx.Save(models.ShamirPublicKeys).Error
	})

	GlobalUploadShamirStatus.Lock()
	status := &GlobalUploadShamirStatus

	status.ShamirUpdating = false
	status.ShamirUpdateReady = false
	status.WarningMessage = warningMessage.String()
	for userID := range status.UploadedShares {
		delete(status.UploadedShares, userID)
	}
	status.UploadedSharesIdentityNames = nil
	status.NewPublicKeys = nil
	status.NowUserID = 0

	var subject string
	var content []byte

	if err != nil {
		// rollback
		status.FailMessage = err.Error()
		status.NewPublicKeys = models.ShamirPublicKeys
		status.CurrentPublicKeys = oldShamirPublicKey
		models.ShamirPublicKeys = oldShamirPublicKey

		if models.DB.Migrator().HasTable(backupShamirTableName) {
			err := models.DB.Migrator().RenameTable(backupShamirTableName, shamirTableName)
			if err != nil {
				log.Println(err.Error())
			}
		}

		subject = "shamir update failed"
	} else {
		subject = "shamir update success"
	}

	content, err = json.Marshal(&status)
	if err != nil {
		content = []byte(err.Error())
	}

	GlobalUploadShamirStatus.Unlock()

	// send email to update
	err = utils.SendEmail(subject, string(content), []string{config.Config.EmailDev})
	if err != nil {
		log.Printf("error sending emails: %v\nsubject: %v\ncontent: %v", err.Error(), subject, string(content))
	}

	log.Println("updateShamir function finished")
}

package apis

// apis in this page won't check permission, and should be terminated by api gateway in production environment

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/gofiber/fiber/v2"
	"github.com/opentreehole/go-common"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"auth_next/config"
	. "auth_next/models"
	"auth_next/utils"
	"auth_next/utils/shamir"
)

func currentShamirThreshold() int {
	return config.ShamirThreshold(len(ShamirPublicKeys))
}

func canUpdateShamir(status *ShamirStatusResponse) bool {
	return len(status.UploadedSharesIdentityNames) >= currentShamirThreshold() &&
		config.IsValidShamirKeyCount(len(status.NewPublicKeys))
}

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
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func GetPGPMessageByUserID(c *fiber.Ctx) error {
	// get identity
	var query PGPMessageRequest
	err := common.ValidateQuery(c, &query)
	if err != nil {
		return err
	}

	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can get pgp message")
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
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func ListPGPMessages(c *fiber.Ctx) error {
	// get identity
	var query PGPMessageRequest
	err := common.ValidateQuery(c, &query)
	if err != nil {
		return err
	}

	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can get pgp message")
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
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func UploadAllShares(c *fiber.Ctx) error {
	// get shares
	var body UploadSharesRequest
	err := common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can upload shares")
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

	if canUpdateShamir(&status.ShamirStatusResponse) {
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

	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can upload public keys")
	}

	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	if !config.IsValidShamirKeyCount(len(body.Data)) {
		return common.BadRequest("公钥数量必须是大于 1 的奇数")
	}

	// save public keys
	status.NewPublicKeys = nil
	identityNames := make(map[string]struct{}, len(body.Data))
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
		identityName := publicKey.GetEntity().PrimaryIdentity().Name
		if _, ok := identityNames[identityName]; ok {
			return common.BadRequest(fmt.Sprintf("duplicate public key identity name: %v", identityName))
		}
		identityNames[identityName] = struct{}{}

		// save new public keys with assigned id, for save to database
		status.NewPublicKeys = append(status.NewPublicKeys, ShamirPublicKey{
			ID:               i + 1,
			IdentityName:     identityName,
			ArmoredPublicKey: armoredPublicKey,
			PublicKey:        publicKeyRing,
		})
	}

	if canUpdateShamir(&status.ShamirStatusResponse) {
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
	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can get shamir status")
	}

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
	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can update shamir")
	}

	GlobalUploadShamirStatus.Lock()
	defer GlobalUploadShamirStatus.Unlock()
	status := &GlobalUploadShamirStatus

	if status.ShamirUpdating {
		return common.BadRequest("正在重新加解密，请不要重复触发")
	}
	if !status.ShamirUpdateReady {
		if len(status.UploadedSharesIdentityNames) < currentShamirThreshold() {
			return common.BadRequest("坐标点数量不够，无法解密")
		} else if !config.IsValidShamirKeyCount(len(status.NewPublicKeys)) {
			return common.BadRequest("公钥数量必须是大于 1 的奇数")
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
// @Router /shamir/refresh/_webvpn [patch]
// @Success 204
// @Failure 403 {object} common.MessageResponse "非管理员"
// @failure 500 {object} common.MessageResponse
func RefreshShamir(c *fiber.Ctx) error {
	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can refresh shamir")
	}

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
	decryptThreshold := config.ShamirThreshold(len(oldShamirPublicKey))

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

	shamirEmails := make([]ShamirEmail, 0, len(ShamirPublicKeys)*len(userIDs))

	err = func() (err error) {
		// concurrently compute
		type updateResult struct {
			userID  int
			emails  []ShamirEmail
			warning string
			err     error
		}

		taskChan := make(chan int)
		resultChan := make(chan updateResult, 100)

		// task executor
		var wg sync.WaitGroup
		for i := 0; i < runtime.NumCPU(); i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for userID := range taskChan {
					// get shares
					shares := allShares[userID]
					if len(shares) < decryptThreshold {
						resultChan <- updateResult{
							userID:  userID,
							warning: fmt.Sprintf("user %v don't have enough shares\n", userID),
						}
						continue
					}

					// decrypt email
					email, ok := decryptEmailWithThreshold(shares, decryptThreshold)
					if !ok {
						resultChan <- updateResult{
							userID: userID,
							err:    fmt.Errorf("[email decrypt error] invalid shares, user_id = %d", userID),
						}
						continue
					}
					if !utils.ValidateEmail(email) {
						if !utils.IsEmail(email) {
							// decrypt error
							resultChan <- updateResult{
								userID: userID,
								err:    fmt.Errorf("[email decrypt error] invalid email, user_id = %d, email: %v", userID, email),
							}
							continue
						}

						// filter invalid emails
						resultChan <- updateResult{
							userID:  userID,
							warning: fmt.Sprintf("user %v don't have valid email: %v\n", userID, email),
						}
						continue
					}

					// generate shamir emails
					innerShamirEmails, innerErr := GenerateShamirEmails(userID, email)
					if innerErr != nil {
						resultChan <- updateResult{userID: userID, err: innerErr}
						continue
					}

					resultChan <- updateResult{userID: userID, emails: innerShamirEmails}
				}
			}()
		}

		// task sender
		go func() {
			for _, userID := range userIDs {
				taskChan <- userID
			}
			close(taskChan)
			wg.Wait()
			close(resultChan)
		}()

		// receive task results
		taskCount := 0
		successCount := 0
		skippedCount := 0
		for result := range resultChan {
			if result.err != nil {
				skippedCount++
				log.Warn().
					Err(result.err).
					Int("user_id", result.userID).
					Str("scope", taskScope).
					Msg("skip user during shamir update")
				warningMessage.WriteString(result.err.Error())
				warningMessage.WriteByte('\n')
			} else if result.warning != "" {
				skippedCount++
				log.Warn().
					Int("user_id", result.userID).
					Str("warning", result.warning).
					Str("scope", taskScope).
					Msg("skip user during shamir update")
				warningMessage.WriteString(result.warning)
			} else if result.emails != nil {
				successCount++
				shamirEmails = append(shamirEmails, result.emails...)
			}
			taskCount++
			if taskCount%1000 == 0 {
				log.Info().Str("scope", taskScope).Msgf("processed %v users", taskCount)
			}
			GlobalUploadShamirStatus.Lock()
			GlobalUploadShamirStatus.NowUserID = taskCount
			GlobalUploadShamirStatus.Unlock()
		}
		if successCount*100 < len(userIDs)*99 {
			err = fmt.Errorf(
				"shamir update success rate below 99%%: success=%d skipped=%d total=%d",
				successCount,
				skippedCount,
				len(userIDs),
			)
			log.Error().
				Err(err).
				Int("success_count", successCount).
				Int("skipped_count", skippedCount).
				Int("total_count", len(userIDs)).
				Str("scope", taskScope).
				Msg("abort shamir update")
			return err
		}
		if skippedCount > 0 {
			log.Warn().
				Int("success_count", successCount).
				Int("skipped_count", skippedCount).
				Int("total_count", len(userIDs)).
				Str("scope", taskScope).
				Msg("continue shamir update with skipped users")
		}

		return DB.Session(&gorm.Session{
			Logger:            DB.Logger.LogMode(logger.Warn),
			NewDB:             true,
			AllowGlobalUpdate: true,
			CreateBatchSize:   1000,
		}).Transaction(func(tx *gorm.DB) error {

			// Replace only successful users. Skipped users keep their existing rows
			// for manual cleanup or later regeneration.
			successfulUserIDs := make([]int, 0, successCount)
			successfulUserIDSet := make(map[int]struct{}, successCount)
			for _, shamirEmail := range shamirEmails {
				if _, ok := successfulUserIDSet[shamirEmail.UserID]; !ok {
					successfulUserIDSet[shamirEmail.UserID] = struct{}{}
					successfulUserIDs = append(successfulUserIDs, shamirEmail.UserID)
				}
			}

			if len(successfulUserIDs) > 0 {
				for start := 0; start < len(successfulUserIDs); start += 1000 {
					end := min(start+1000, len(successfulUserIDs))
					err = tx.
						Where("user_id IN ?", successfulUserIDs[start:end]).
						Delete(&ShamirEmail{}).
						Error
					if err != nil {
						return err
					}
				}
			}

			// insert new shamir emails
			err = tx.Create(shamirEmails).Error
			if err != nil {
				return err
			}

			// save new public keys
			err = tx.Where("1 = 1").Delete(&ShamirPublicKey{}).Error
			if err != nil {
				return err
			}
			err = tx.Create(ShamirPublicKeys).Error
			if err != nil {
				return err
			}

			return nil
		})
	}()

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
		status.FailMessage = ""
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

// UploadUserShares godoc
//
// @Summary upload shares of one user
// @Tags shamir
// @Produce json
// @Router /shamir/decrypt [post]
// @Param shares body UploadShareRequest true "shares"
// @Success 200 {object} common.MessageResponse{data=IdentityNameResponse}
// @Failure 400 {object} common.MessageResponse
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func UploadUserShares(c *fiber.Ctx) error {
	var body UploadShareRequest
	err := common.ValidateBody(c, &body)
	if err != nil {
		return err
	}

	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can upload user shares")
	}

	GlobalUserSharesStatus.Lock()
	defer GlobalUserSharesStatus.Unlock()
	status := &GlobalUserSharesStatus

	// save Identity Names for User
	uploadedIdentityNames := status.UploadedSharesIdentityNames[body.UserID]
	uploadedIndex := -1
	for i, identityName := range uploadedIdentityNames {
		if identityName == body.IdentityName {
			uploadedIndex = i
			break
		}
	}

	// save shares
	if uploadedIndex >= 0 && uploadedIndex < len(status.UploadedShares[body.UserID]) {
		status.UploadedShares[body.UserID][uploadedIndex] = body.Share
	} else {
		status.UploadedSharesIdentityNames[body.UserID] = append(uploadedIdentityNames, body.IdentityName)
		status.UploadedShares[body.UserID] = append(status.UploadedShares[body.UserID], body.Share)
	}

	if len(status.UploadedSharesIdentityNames[body.UserID]) >= currentShamirThreshold() {
		status.ShamirUploadReady[body.UserID] = true
	}

	return c.JSON(common.MessageResponse{
		Message: "上传成功",
		Data: Map{
			"identity_name":      body.IdentityName,
			"user_id":            body.UserID,
			"now_updated_shares": status.UploadedSharesIdentityNames[body.UserID],
		},
	})
}

// GetDecryptedUserEmail godoc
//
// @Summary get decrypted email of one user
// @Tags shamir
// @Produce json
// @Router /shamir/decrypt/{user_id} [get]
// @Param user_id path int true "Target UserID"
// @Success 200 {object} DecryptedUserEmailResponse
// @Failure 400 {object} common.MessageResponse
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func GetDecryptedUserEmail(c *fiber.Ctx) error {
	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can decrypt email")
	}

	// get target user id
	targetUserID, err := c.ParamsInt("id", 0)
	if err != nil {
		return err
	}
	if targetUserID <= 0 {
		return errors.New("user_id at least 1")
	}

	GlobalUserSharesStatus.Lock()
	defer GlobalUserSharesStatus.Unlock()
	status := &GlobalUserSharesStatus

	if !status.ShamirUploadReady[targetUserID] {
		if len(status.UploadedSharesIdentityNames[targetUserID]) < currentShamirThreshold() {
			return common.BadRequest("坐标点数量不够，无法解密")
		} else {
			return common.BadRequest("无法解密")
		}
	}

	response, ok := decryptUserEmailWithThreshold(
		targetUserID,
		status.UploadedShares[targetUserID],
		status.UploadedSharesIdentityNames[targetUserID],
		currentShamirThreshold(),
	)
	if !ok {
		return common.BadRequest("解密失败，请重新输入坐标点")
	}

	delete(status.UploadedShares, targetUserID)
	delete(status.UploadedSharesIdentityNames, targetUserID)
	status.ShamirUploadReady[targetUserID] = false

	return c.JSON(response)
}

func decryptEmailWithThreshold(shares shamir.Shares, threshold int) (string, bool) {
	n := len(shares)
	if n < threshold {
		return "", false
	}

	var result string
	ok := forEachShareCombination(n, threshold, func(selected []int) bool {
		email := shamir.Decrypt(selectedShares(shares, selected))
		if utils.ValidateEmail(email) {
			result = email
			return false
		}
		return true
	})
	if !ok {
		return result, true
	}

	return "", false
}

func decryptUserEmailWithThreshold(userID int, shares shamir.Shares, identityNames []string, threshold int) (DecryptedUserEmailResponse, bool) {
	n := len(shares)
	if len(identityNames) < n {
		n = len(identityNames)
	}
	if n < threshold {
		return DecryptedUserEmailResponse{}, false
	}

	var result DecryptedUserEmailResponse
	ok := forEachShareCombination(n, threshold, func(selected []int) bool {
		response := DecryptedUserEmailResponse{
			UserID:        userID,
			UserEmail:     shamir.Decrypt(selectedShares(shares, selected)),
			IdentityNames: selectedIdentityNames(identityNames, selected),
		}
		if utils.ValidateEmail(response.UserEmail) {
			result = response
			return false
		}
		return true
	})
	if !ok {
		return result, true
	}

	return DecryptedUserEmailResponse{}, false
}

func forEachShareCombination(n, threshold int, fn func([]int) bool) bool {
	if threshold <= 0 || threshold > n {
		return true
	}

	selected := make([]int, 0, threshold)
	var walk func(start int) bool
	walk = func(start int) bool {
		if len(selected) == threshold {
			combination := make([]int, threshold)
			copy(combination, selected)
			return fn(combination)
		}

		remaining := threshold - len(selected)
		for i := start; i <= n-remaining; i++ {
			selected = append(selected, i)
			if !walk(i + 1) {
				return false
			}
			selected = selected[:len(selected)-1]
		}
		return true
	}
	return walk(0)
}

func selectedShares(shares shamir.Shares, selected []int) shamir.Shares {
	result := make(shamir.Shares, 0, len(selected))
	for _, i := range selected {
		result = append(result, shares[i])
	}
	return result
}

func selectedIdentityNames(identityNames []string, selected []int) []string {
	result := make([]string, 0, len(selected))
	for _, i := range selected {
		result = append(result, identityNames[i])
	}
	return result
}

// GetDecryptStatusbyUserID godoc
//
// @Summary get decrypt status by userID
// @Tags shamir
// @Produce json
// @Router /shamir/decrypt/status/{user_id} [get]
// @Param user_id path int true "Target UserID"
// @Success 200 {object} ShamirUserSharesResponse
// @Failure 403 {object} common.MessageResponse "非管理员"
// @Failure 500 {object} common.MessageResponse
func GetDecryptStatusbyUserID(c *fiber.Ctx) error {
	// identify shamir admin
	userID, err := common.GetUserID(c)
	if err != nil {
		return err
	}

	if !IsShamirAdmin(userID) {
		return common.Forbidden("only shamir admin can get decrypt status")
	}

	// get target user id
	targetUserID, err := c.ParamsInt("id", 0)
	if err != nil {
		return err
	}
	if targetUserID <= 0 {
		return errors.New("user_id at least 1")
	}

	GlobalUserSharesStatus.Lock()
	defer GlobalUserSharesStatus.Unlock()

	return c.JSON(ShamirUserSharesResponse{
		ShamirUploadReady:           GlobalUserSharesStatus.ShamirUploadReady[targetUserID],
		UploadedSharesIdentityNames: GlobalUserSharesStatus.UploadedSharesIdentityNames[targetUserID],
	})
}

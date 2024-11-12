package tests

import (
	"context"
	"fmt"
	tokengenerator "github.com/ascenmmo/token-generator/token_generator"
	tokentype "github.com/ascenmmo/token-generator/token_type"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"runtime"
	"strconv"
	"testing"
	"time"
)

const (
	key = "1234-1234-1234-1234-1234-1234-12"
)

func TestGeneratorJWT(t *testing.T) {
	runtime.GOMAXPROCS(1)
	gameID := uuid.NewMD5(uuid.New(), []byte(strconv.Itoa(1)))
	roomID := uuid.NewMD5(uuid.New(), []byte(strconv.Itoa(1)))
	userID := uuid.NewMD5(uuid.New(), []byte(fmt.Sprintf("user %d", 1)))
	info := tokentype.Info{
		GameID: gameID,
		RoomID: roomID,
		UserID: userID,
		TTL:    time.Second * 5,
	}

	generator, err := tokengenerator.NewTokenGenerator(key)
	assert.Nil(t, err, "NewTokenGenerator err expected nil")

	startCreating := time.Now()
	token, err := generator.GenerateToken(info, tokengenerator.JWT)
	assert.Nil(t, err, "GenerateToken err expected nil")
	assert.NotNil(t, token, "GenerateToken token expected nil")
	endCreating := time.Now()

	timesDur := []time.Duration{}
	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(time.Second*1))

	func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				startParse := time.Now()
				parseToken, err := generator.ParseToken(token)
				assert.Nil(t, err, "ParseToken err expected nil")
				assert.Equal(t, parseToken, info, "ParseToken Equal parseToken and info")
				endParse := time.Now()

				timesDur = append(timesDur, endParse.Sub(startParse))
			}
		}
	}()

	min := time.Duration(0)
	max := time.Duration(0)
	for _, v := range timesDur {
		if min == 0 {
			min = v
		}
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	t.Log("GenerateToken :", endCreating.Sub(startCreating))
	t.Log("countParse :", len(timesDur))
	t.Log("maxParseTime :", max)
	t.Log("minParseTime :", min)
}

func TestGeneratorAESGCM(t *testing.T) {
	runtime.GOMAXPROCS(1)
	gameID := uuid.NewMD5(uuid.New(), []byte(strconv.Itoa(1)))
	roomID := uuid.NewMD5(uuid.New(), []byte(strconv.Itoa(1)))
	userID := uuid.NewMD5(uuid.New(), []byte(fmt.Sprintf("user %d", 1)))
	info := tokentype.Info{
		GameID: gameID,
		RoomID: roomID,
		UserID: userID,
		TTL:    time.Second * 5,
	}

	generator, err := tokengenerator.NewTokenGenerator(key)
	assert.Nil(t, err, "NewTokenGenerator err expected nil")

	startCreating := time.Now()
	token, err := generator.GenerateToken(info, tokengenerator.AESGCM)
	assert.Nil(t, err, "GenerateToken err expected nil")
	assert.NotNil(t, token, "GenerateToken token expected nil")
	endCreating := time.Now()

	timesDur := []time.Duration{}
	ctx, _ := context.WithDeadline(context.Background(), time.Now().Add(time.Second*1))

	func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				startParse := time.Now()
				parseToken, err := generator.ParseToken(token)
				assert.Nil(t, err, "ParseToken err expected nil")
				assert.Equal(t, parseToken, info, "ParseToken Equal parseToken and info")
				endParse := time.Now()

				timesDur = append(timesDur, endParse.Sub(startParse))
			}
		}
	}()

	min := time.Duration(0)
	max := time.Duration(0)
	for _, v := range timesDur {
		if min == 0 {
			min = v
		}
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	t.Log("GenerateToken :", endCreating.Sub(startCreating))
	t.Log("countParse :", len(timesDur))
	t.Log("maxParseTime :", max)
	t.Log("minParseTime :", min)

}

func TestGeneratorHash(t *testing.T) {
	generator, err := tokengenerator.NewTokenGenerator(key)
	assert.Nil(t, err, "NewTokenGenerator err expected nil")

	data := `super123_)"123"''!#!$I()_$.   	≈ç∆œ∆®øπ˜˚¬å˜ƒåƒ∆˚¬`

	hashData, err := generator.GenerateUniqueHash(data)
	assert.Nil(t, err, "GenerateHash err expected nil")

	txt, err := generator.ParseUniqueHash(hashData)
	assert.Nil(t, err, "ParseHash err expected nil")
	assert.Equal(t, data, txt, "data and txt  equal")

	newHashData, err := generator.GenerateUniqueHash(data)
	assert.Nil(t, err, "GenerateHash err expected nil")
	assert.NotEqual(t, hashData, newHashData, "hashData and newHashData not equal")
}

func TestPasswordHash(t *testing.T) {
	generator, err := tokengenerator.NewTokenGenerator(key)
	assert.Nil(t, err, "NewTokenGenerator err expected nil")

	data := `super123_)"123"''!#!$I()_$.   	≈ç∆œ∆®øπ˜˚¬å˜ƒåƒ∆˚¬`

	hashData := generator.PasswordHash(data)
	newHashData := generator.PasswordHash(data)
	assert.Equal(t, hashData, newHashData, "data and hashData  equal")
}

func TestSecretHash(t *testing.T) {
	generator, err := tokengenerator.NewTokenGenerator(key)
	assert.Nil(t, err, "NewTokenGenerator err expected nil")

	watingHash := "27f122d79f96912f18cf01e013b33dfecfcd8e3d01ec5bd4d50c621c1450121938ba4ab864065e4b90e7057d55fc603e8b11c1993e25366643b9745382586621816fd7e2f405793cd6286ea4e67d3305570ba2719dff15bac706"

	data := `1super123_)"123"''!#!$I()_$.   	≈ç∆œ∆®øπ˜˚¬å˜ƒåƒ∆˚¬`

	hashData, err := generator.GenerateSecretHash(data)
	assert.Nil(t, err, "GenerateSecretHash err expected nil")

	newHashData, err := generator.GenerateSecretHash(data)
	assert.Nil(t, err, "GenerateSecretHash err expected nil")

	assert.Equal(t, hashData, newHashData, "newHashData and hashData  equal")
	assert.Equal(t, watingHash, newHashData, "newHashData and watingHash  equal")

	//parsing
	secret, err := generator.ParseSecretHash(hashData)
	assert.Nil(t, err, "ParseSecretHash hashData err expected nil")

	newSecret, err := generator.ParseSecretHash(newHashData)
	assert.Nil(t, err, "ParseSecretHash newHashData err expected nil")

	assert.Equal(t, secret, newSecret)
	assert.Equal(t, data, newSecret)

	//generate parsed data
	newParsedSecretHashData, err := generator.GenerateSecretHash(newSecret)
	assert.Nil(t, err, "GenerateSecretHash newSecret err expected nil")

	assert.Equal(t, hashData, newParsedSecretHashData, "hashData and hashData  equal")
	assert.Equal(t, watingHash, newParsedSecretHashData, "watingHash and newParsedSecretHashData  equal")

	newParsedSecret, err := generator.ParseSecretHash(newParsedSecretHashData)
	assert.Nil(t, err, "ParseSecretHash newHashData err expected nil")

	assert.Equal(t, secret, newParsedSecret)
	assert.Equal(t, data, newParsedSecret)

}

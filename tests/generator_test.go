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

	hashData, err := generator.GenerateHash(data)
	assert.Nil(t, err, "GenerateHash err expected nil")

	txt, err := generator.ParseHash(hashData)
	assert.Nil(t, err, "ParseHash err expected nil")
	assert.Equal(t, data, txt, "data and txt  equal")

	newHashData, err := generator.GenerateHash(data)
	assert.Nil(t, err, "GenerateHash err expected nil")

	fmt.Println(hashData)
	fmt.Println(newHashData)
}

func TestPasswordHash(t *testing.T) {
	generator, err := tokengenerator.NewTokenGenerator(key)
	assert.Nil(t, err, "NewTokenGenerator err expected nil")

	data := `super123_)"123"''!#!$I()_$.   	≈ç∆œ∆®øπ˜˚¬å˜ƒåƒ∆˚¬`

	hashData := generator.PasswordHash(data)
	newHashData := generator.PasswordHash(data)
	assert.Equal(t, hashData, newHashData, "data and hashData  equal")
}

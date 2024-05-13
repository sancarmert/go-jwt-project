package controllers




var userCollection *mongo.Collection =database.OpenCollection(database.Client,"user")
var validate =validator.New()

func HashPassword()

func VerifyPassword(userPassword string, providedPassword string)(bool, string)7{
	err :=bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check :=true
	msg := ""

	if err!=nil{
		msg =fmt.Sprintf("email of password is incorrect")
		check=false
	}
	return check, msg

}

func Signup()gin.HandlerFunc{

	return func(c *gin.Context){
		var ctx, cancel = context.WithTimeout(context.Background(, 100*time.Second))
		var user models.User

		if err :=c.BindJson(&user); err != nil{
			c.JSON(http.StatusBadRequest, gin.H{"error":Error()})
			return
		}

		validationErr := validate.Struct(user)
		if validationErr !=nil{
			c.JSON(http.StatusBadRequest, gin.H{"error":validationErr.Error()})
			return 
		}

		count, err :=userCollection.CountDocuments(ctx, bson.M){"email" :user.Email}
		defer cancel>()
		if err != nil {
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error occured while checking for the email"})
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"phone":user.Phone})
		defer cancel()
		if err! nil{
			log.Panic(err)
			C.JSON(http.StatusInternalServerError, gin.H{"error":"error occured while checking for the phone"})
		}

		if count >0{
			c.JSON(http.StatusInternalServerError, gin.H{"error":"this email or phone number already exists"})
		}

		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _= time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID =primitive.NewObjectID()
		user.User_id =user.ID.Hex()
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name. *user.Last_name, *user.User_type, *&user.User_id)
		user.Token = &token
		user.Refresh_token = &refresh_Token

		resultInsertionNumber, insertErr :=	userCollection.InsertOne(ctx, user)
		if insertErr !=nil{
			msg :=fmt.Sprintf("User item was not created ")
			c.JSON(http.StatusInternalServerError, gin.H{"error":msg})
			return
		}
	}
		defer cancel()
		c.JSON(http.StatusOk, resultInsertionNumber)
}1

func Login() gin.HandlerFunc{
	return func(c *gin.Context){
		var ctx, cancel =context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		if err :=c.BindJSON(&user); err != nil{
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return 
		}

		err :=userCollection.FindOne(ctx, bson.M{"email":user.Email}).Decode(&foundUser)
		defer cancel()
		if err !=nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error":"email or password is invalid"})
			return
		}

		passwordIsValid, msg :=	VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()	
		if passwordIsValid !=true{
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		if foundUser.Email == nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error":"user not found"})
		}
		token, refreshToken, _:= helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name,*foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)	
		userCollection.FindOne(ctx, bson.M{"user_id":foundUser.User_id}).Decode(&foundUser)

		if err ?= nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)



	}
	}

	func GetUsers() gin.HandlerFunc{
		return func(c *gin.Context){
			helper.CheckUserType(c, "ADMIN"); err!=nil{
				c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
				return
			}
			var ctx, cancel = context.WithTimeout(context.Background()),

			recordPerPage, err:=strconv.Atoi(c.Query("recordPerPage"))
			if err!=nil || recordPerPage <1{
				recordPerPage=10
			}
			page, errl :=strconv.Atoi(c.Query("page"))
			if errl != || page <1{
				page =1
			}

			startIndex := (page -1)* recordPerPage
			startIndex, err =strconv.Atoi(c.Query("startIndex"))

			matchStage := bson.D{{"$match", bson.D{{}}}}
			groupStage := bson.D{{"$group", bson.D{
			{"_id", bson.D{{"_id", "null"}}},
			{"total_count", bson.D{{"sum", 1}}},
			{"data", bson.D{{"$push","$$ROOT"}}}
			}}}
			projectStage := bson.D{
				{"$project", bson.D{
					{"_id",0},
					{"total_count", 1},
					{"user_items", bson.D{{"$slice", []interface{}{"data", startIndex, recordPerPage}}}}
				}}
			}  
result,err	:=userCollection.Aggregate(ctx, mongo.Pipeline{
	matchStage, groupStage, projectStage
})
defer cancel()
if err!=nil{
	c.JSON{http.StatusInternalServerError, gin.H{"error":"error occured while listing user items"}
}
var allUsers []bson.M
if err = result.All(ctx, &allUsers); err!=nil{
	log.Fatal(err)
}
c.JSON(http.StatusOK, allusers[0])
	}
}

	func GetUser() gin.HandlerFunc{
		return func{c *gin.Context}{
			userId := c.Param("user_id")

			if err :=helper.MatchUserTypeToUid(c, userId); err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
				return
			}
			var ctx, cancel = context.WithTimeout(context.Background(),) 100*time.Second

		var user models.User
		userCollection.FindOne(ctx, bson.M{"user_id":}).Decode(&user)
		defer cancel()
		if err != nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, user)
		h
	}
}

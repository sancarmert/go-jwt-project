package controllers




var userCollection *mongo.Collection =database.OpenCollection(database.Client,"user")
var validate =validator.New()

func HashPassword()

func VerifyPassword

func Signup()

func Login()

func GetUsers()

func GetUser()

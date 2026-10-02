package database

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var Client *mongo.Client = CreateMongoClient()

func CreateMongoClient() *mongo.Client {
	godotenv.Overload()
	MongoDbURI := os.Getenv("MONGODB_URI")
	client, err := mongo.NewClient(options.Client().ApplyURI(MongoDbURI))
	if err != nil {
		log.Fatal(err)
	}

	var ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer cancel()
	// Never log the URI: it carries the database credentials
	fmt.Println("Connected to MongoDB")
	return client
}

// Database name comes from MONGODB_DATABASE; the default keeps the original behaviour
func databaseName() string {
	if name := os.Getenv("MONGODB_DATABASE"); name != "" {
		return name
	}
	return "go-mongodb"
}

func OpenCollection(client *mongo.Client, collectionName string) *mongo.Collection {
	return client.Database(databaseName()).Collection(collectionName)
}

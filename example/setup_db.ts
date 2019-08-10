import {
  DynamoDBClient,
  createClient
} from "https://denopkg.com/chiefbiiko/dynamodb/mod.ts";

const ENV: { [key: string]: any } = Deno.env();

const ddbc: DynamoDBClient = createClient({
  accessKeyId: ENV.ACCESS_KEY_ID || "fraud",
  secretAccessKey: ENV.SECRET_ACCESS_KEY || "fraud",
  region: "local"
});

async function main(): Promise<void> {
  let result: { [key: string]: any } = await ddbc.listTables();

  if (!result.TableNames.includes("users")) {
    await ddbc.createTable({
      TableName: "users",
      KeySchema: [{ KeyType: "HASH", AttributeName: "id" }],
      AttributeDefinitions: [{ AttributeName: "id", AttributeType: "S" }],
      ProvisionedThroughput: { ReadCapacityUnits: 1, WriteCapacityUnits: 1 }
    });
  }

  if (!result.TableNames.includes("users_emails")) {
    await ddbc.createTable({
      TableName: "users_emails",
      KeySchema: [{ KeyType: "HASH", AttributeName: "email" }],
      AttributeDefinitions: [{ AttributeName: "email", AttributeType: "S" }],
      ProvisionedThroughput: { ReadCapacityUnits: 1, WriteCapacityUnits: 1 }
    });
  }
}

main();

# Secrets_AWS

> Secrets management is the use of tools and methods to securely store, access and centrally manage the lifecycle of digital authentication credentials. This includes sensitive data such as passwords, keys, APIs, tokens, and certificates.

And lately with all the cyber security threats this is very important.

And we have seen interesting in this practice for Java / Scala Spark Migrations.

So in this short guide we will discuss Secret Management in AWS.

AWS provides the [AWS Secret Manager](https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html)

Again quoting from the AWS documentation: 

> Secrets Manager enables you to replace hardcoded credentials in your code, including passwords, with an API call to Secrets Manager to retrieve the secret programmatically. This helps ensure the secret can't be compromised by someone examining your code, because the secret no longer exists in the code. Also, you can configure Secrets Manager to automatically rotate the secret for you according to a specified schedule. This enables you to replace long-term secrets with short-term ones, significantly reducing the risk of compromise.


So first. 

Let's start with a secret. [We need to create one](https://docs.aws.amazon.com/secretsmanager/latest/userguide/managing-secrets.html):

1. Open the Secrets Manager console at https://console.aws.amazon.com/secretsmanager/. Choose Store a new secret.
2. On the Store a new secret page, do the following:
For Secret type, choose other type of secret (for example credentials for an Snowflake Database):
You need to setup the key names and a key values. Or you can just edit is as plain text and enter an JSON for example something like this:

```json
{
 "user":"xxx",
 "pasword":"xxx",
 "account":"xxx",
 "role":"role",
 "warehouse":"xxx",
"database":"xxx",
"session":"xxx"
}
```

For Encryption key, choose the AWS KMS key that Secrets Manager uses to encrypt the secret value:

For most cases, choose aws/secretsmanager to use the AWS managed key for Secrets Manager. There is no cost for using this key.
If you need to access the secret from another AWS account, choose a customer managed key from the list or choose Add new key to create one. You will be charged for KMS keys that you create.
You must have the following permissions to the key: kms:Encrypt, kms:Decrypt, and kms:GenerateDataKey. 
Choose Next.
On the Secret name and description page, do the following: Enter a descriptive Secret name and Description.

The Secret name you enter here will ne needed later.

Click Next and then Next

The last screen has an Store option. It also shows code snippets on how to read your secret:

### Java
``` Java
// Use this code snippet in your app.
// If you need more information about configurations or implementing the sample code, visit the AWS docs:
// https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/java-dg-samples.html#prerequisites

public static void getSecret() {

    String secretName = "SnowflakeCredentials";
    String region = "us-east-1";

    // Create a Secrets Manager client
    AWSSecretsManager client  = AWSSecretsManagerClientBuilder.standard()
                                    .withRegion(region)
                                    .build();
    
    // In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    // See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    // We rethrow the exception by default.
    
    String secret, decodedBinarySecret;
    GetSecretValueRequest getSecretValueRequest = new GetSecretValueRequest()
                    .withSecretId(secretName);
    GetSecretValueResult getSecretValueResult = null;

    try {
        getSecretValueResult = client.getSecretValue(getSecretValueRequest);
    } catch (DecryptionFailureException e) {
        // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    } catch (InternalServiceErrorException e) {
        // An error occurred on the server side.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    } catch (InvalidParameterException e) {
        // You provided an invalid value for a parameter.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    } catch (InvalidRequestException e) {
        // You provided a parameter value that is not valid for the current state of the resource.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    } catch (ResourceNotFoundException e) {
        // We can't find the resource that you asked for.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    }

    // Decrypts secret using the associated KMS key.
    // Depending on whether the secret is a string or binary, one of these fields will be populated.
    if (getSecretValueResult.getSecretString() != null) {
        secret = getSecretValueResult.getSecretString();
    }
    else {
        decodedBinarySecret = new String(Base64.getDecoder().decode(getSecretValueResult.getSecretBinary()).array());
    }

    // Your code goes here.
}
```

### Java API v2
```Java
// Use this code snippet in your app.
// If you need more information about configurations or implementing the sample code, visit the AWS docs:
// https://docs.aws.amazon.com/sdk-for-java/v1/developer-guide/java-dg-samples.html#prerequisites

public static void getSecret() {

    String secretName = "SnowflakeCredentials";
    Region region = Region.of("us-east-1");

    // Create a Secrets Manager client
    SecretsManagerClient client = SecretsManagerClient.builder()
            .region(region)
            .build();

    // In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    // See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    // We rethrow the exception by default.

    String secret, decodedBinarySecret;
    GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
            .secretId(secretName)
            .build();
    GetSecretValueResponse getSecretValueResponse = null;

    try {
        getSecretValueResponse = client.getSecretValue(getSecretValueRequest);
    } catch (DecryptionFailureException e) {
        // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    } catch (InternalServiceErrorException e) {
        // An error occurred on the server side.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    } catch (InvalidParameterException e) {
        // You provided an invalid value for a parameter.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    } catch (InvalidRequestException e) {
        // You provided a parameter value that is not valid for the current state of the resource.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    } catch (ResourceNotFoundException e) {
        // We can't find the resource that you asked for.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw e;
    }

    // Decrypts secret using the associated KMS key.
    // Depending on whether the secret is a string or binary, one of these fields will be populated.
    if (getSecretValueResponse.secretString() != null) {
        secret = getSecretValueResponse.secretString();
    }
    else {
        decodedBinarySecret = new String(Base64.getDecoder().decode(getSecretValueResponse.secretBinary().asByteBuffer()).array());
    }

    // Your code goes here.
}
```
### Javascript
```js
// Use this code snippet in your app.
// If you need more information about configurations or implementing the sample code, visit the AWS docs:
// https://aws.amazon.com/developers/getting-started/nodejs/

// Load the AWS SDK
var AWS = require('aws-sdk'),
    region = "us-east-1",
    secretName = "SnowflakeCredentials",
    secret,
    decodedBinarySecret;

// Create a Secrets Manager client
var client = new AWS.SecretsManager({
    region: region
});

// In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
// See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
// We rethrow the exception by default.

client.getSecretValue({SecretId: secretName}, function(err, data) {
    if (err) {
        if (err.code === 'DecryptionFailureException')
            // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        else if (err.code === 'InternalServiceErrorException')
            // An error occurred on the server side.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        else if (err.code === 'InvalidParameterException')
            // You provided an invalid value for a parameter.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        else if (err.code === 'InvalidRequestException')
            // You provided a parameter value that is not valid for the current state of the resource.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
        else if (err.code === 'ResourceNotFoundException')
            // We can't find the resource that you asked for.
            // Deal with the exception here, and/or rethrow at your discretion.
            throw err;
    }
    else {
        // Decrypts secret using the associated KMS key.
        // Depending on whether the secret is a string or binary, one of these fields will be populated.
        if ('SecretString' in data) {
            secret = data.SecretString;
        } else {
            let buff = new Buffer(data.SecretBinary, 'base64');
            decodedBinarySecret = buff.toString('ascii');
        }
    }
    
    // Your code goes here. 
});
```
### CSharp
```cs
/*
 *	Use this code snippet in your app.
 *	If you need more information about configurations or implementing the sample code, visit the AWS docs:
 *	https://aws.amazon.com/developers/getting-started/net/
 *	
 *	Make sure to include the following packages in your code.
 *	
 *	using System;
 *	using System.IO;
 *
 *	using Amazon;
 *	using Amazon.SecretsManager;
 *	using Amazon.SecretsManager.Model;
 *
 */

/*
 * AWSSDK.SecretsManager version="3.3.0" targetFramework="net45"
 */
public static void GetSecret()
{
    string secretName = "SnowflakeCredentials";
    string region = "us-east-1";
    string secret = "";

    MemoryStream memoryStream = new MemoryStream();

    IAmazonSecretsManager client = new AmazonSecretsManagerClient(RegionEndpoint.GetBySystemName(region));

    GetSecretValueRequest request = new GetSecretValueRequest();
    request.SecretId = secretName;
    request.VersionStage = "AWSCURRENT"; // VersionStage defaults to AWSCURRENT if unspecified.

    GetSecretValueResponse response = null;

    // In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    // See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    // We rethrow the exception by default.

    try
    {
        response = client.GetSecretValueAsync(request).Result;
    }
    catch (DecryptionFailureException e)
    {
        // Secrets Manager can't decrypt the protected secret text using the provided KMS key.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw;
    }
    catch (InternalServiceErrorException e)
    {
        // An error occurred on the server side.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw;
    }
    catch (InvalidParameterException e)
    {
        // You provided an invalid value for a parameter.
        // Deal with the exception here, and/or rethrow at your discretion
        throw;
    }
    catch (InvalidRequestException e)
    {
        // You provided a parameter value that is not valid for the current state of the resource.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw;
    }
    catch (ResourceNotFoundException e)
    {
        // We can't find the resource that you asked for.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw;
    }
    catch (System.AggregateException ae)
    {
        // More than one of the above exceptions were triggered.
        // Deal with the exception here, and/or rethrow at your discretion.
        throw;
    }

    // Decrypts secret using the associated KMS key.
    // Depending on whether the secret is a string or binary, one of these fields will be populated.
    if (response.SecretString != null)
    {
        secret = response.SecretString;
    }
    else
    {
        memoryStream = response.SecretBinary;
        StreamReader reader = new StreamReader(memoryStream);
        string decodedBinarySecret = System.Text.Encoding.UTF8.GetString(Convert.FromBase64String(reader.ReadToEnd()));
    }

    // Your code goes here.
}
```
### python

```python
# Use this code snippet in your app.
# If you need more information about configurations or implementing the sample code, visit the AWS docs:   
# https://aws.amazon.com/developers/getting-started/python/

import boto3
import base64
from botocore.exceptions import ClientError


def get_secret():

    secret_name = "SnowflakeCredentials"
    region_name = "us-east-1"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    # In this sample we only handle the specific exceptions for the 'GetSecretValue' API.
    # See https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
    # We rethrow the exception by default.

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            # Secrets Manager can't decrypt the protected secret text using the provided KMS key.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            # An error occurred on the server side.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            # You provided an invalid value for a parameter.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            # You provided a parameter value that is not valid for the current state of the resource.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            # We can't find the resource that you asked for.
            # Deal with the exception here, and/or rethrow at your discretion.
            raise e
    else:
        # Decrypts secret using the associated KMS key.
        # Depending on whether the secret is a string or binary, one of these fields will be populated.
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
        else:
            decoded_binary_secret = base64.b64decode(get_secret_value_response['SecretBinary'])
            
    # Your code goes here. 
```

We have provided some test code in Java which can be used in SnowPark Java and SnowPark Scala projects. 

Ok now that you have a secret.  You need an IAM Role.

1. Sign in to the AWS Management Console and open the IAM console at https://console.aws.amazon.com/iam/.

2. In the navigation pane of the IAM console, choose Roles, and then choose Create role.

3. For Select trusted entity, choose AWS service. For Use case you can select EC2.

Click Next
When adding a policy filter it by typing Secret.

You will see something like SecretManagerAccess with a content like:
```json
{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Action": [
            "secretsmanager:Describe*",
            "secretsmanager:Get*",
            "secretsmanager:List*"
        ],
        "Resource": "*"
    }
}
```
For tests you can use that, but it is better if you create an specific policy just for the secret you just created, you an go to the secret and 
get the ARN which will look like this: arn:aws:secretsmanager:us-east-1:999999999999:secret:SnowflakeCredentials-MtznPD

For example:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "VisualEditor0",
            "Effect": "Allow",
            "Action": "secretsmanager:GetSecretValue",
            "Resource": "arn:aws:secretsmanager:us-east-1:999999999999:secret:SnowflakeCredentials-MtznPD"
        }
    ]
}
```
After adding the policy click Next and then select CreateRole


Ok now, the reading the secrets part.


Lets look at two options.

1. By leveraging the ACCESS_KEY and SECRET_KEY

In this case we just assume that in your environment there will be variables like:

AWS_ACCESS_KEY_ID (or AWS_ACCESS_KEY) and 
AWS_SECRET_KEY (or AWS_SECRET_ACCESS_KEY) 

already set. 
You can use the code in the repo 

Setup the test code:
```
git clone https://github.com/MobilizeNet/Secrets_AWS.git
```

Running the example:
```
gradle :readsecret --args="SnowflakeCredentials"
```

2. By leverage the EC2 integration

In this case you can associate a role with an EC2 instance.

You can create an EC2 instance with Amazon Linux

Setting up the instance:
```
sudo amazon-linux-extras install java-openjdk11
sudo yum install git
curl -s "https://get.sdkman.io" | bash
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk install gradle
```

Setup the test code:
```
git clone https://github.com/MobilizeNet/Secrets_AWS.git
```

Running the example:
```
gradle :readsecretEC2 --args="SnowflakeCredentials"
```
> NOTE: if you have problems with the java version use sdk install java

## api

### Root

`http://localhost.com:8888/`

### Publish
* **Purpose**
	
	Persist metadata for a musical composition to the database.

* **URL**

	`/publish`

* **Method**

	`POST`

* **Data Params**
	```javascript
	u: {
		// Required
		composerIds: [array hexadecimal],
		name: [string],

		// Required if multiple composers 
		signatures: [array base58],
		splits: [array integer],
					
		// Optional
		inLanguage: [string],
		iswcCode: [alphanumeric & special characters],
		publisherId: [hexadecimal],
		url: [url]
	}
	``` 
		
* **Success Response**

	* **Code**: 200
	
		**Example**: 
		```javascript
		{ 
			"@context": "<context placeholder>",
			"@type": "MusicComposition",
			"composer": {
				"@id": "<composerId>"
			},
			"inLanguage": "<inLanguage>",	// ex. "EN"
			"iswcCode": "<iswcCode>",	// ex. "T-034.524.680-1"
			"name": "<name>",
			"publisher": {
				"@id": "<publisherId>"
			},
			"url": "<url>"
		} 
		```

* **Error Response**
	
	* **Code**: 400

	* **Code**: 404

		**Message**: Not logged in


### License
* **Purpose**
	
	Persist a license to the database.

* **URL**

	`/license`

* **Method**
	
	`POST`

* **Data Params**
	```javascript
	u: {
		// Required
		licenseForIds: [array hexadecimal],
		licenseHolderIds: [array hexadecimal],
		licenserId: [hexadecimal],
		validFrom: [date],
		validTo: [date],

		// Required if licenser is not composer/artist of licensed works
		rightIds: [array hexadecimal]
	}
	```
	
* **Success Response**

	* **Code**: 200
	
		**Example**:
		```javascript
		{
			"@context": "<context placeholder>",
			"@type": "License",
			"licenseFor": [
				{
					"@id": "<licenseForId>",
					"hasRight": {
						"@id": "<rightId>"
					}
				}
			],
			"licenseHolder": [
				{
					"@id": "<licenseHolderId1>"
				},
				{
					"@id": "<licenseHolderId2>"
				},
				{
					"@id": "<licenseHolderId3>"
				}
			],
			"licenser": {
				"@id": "<licenserId>"
			},
			"validFrom": "<validFrom>",	// ex. "2020-01-01"
			"validThrough": "<validThrough>"	// ex. "2024-01-01"
		}
		```

* **Error Response**
	
	* **Code**: 400

	* **Code**: 404

		**Message**: Not logged in

### Login
* **Purpose**

	Validate user credentials and keep them in memory for remainder of session. 
	
* **URL**

	`/login`
	
* **Method**

	`POST`
	
* **Data Params**
	```javascript
	u: {
		// Required
		privateKey: [base58],
		userId: [hexadecimal]
	}
	```

* **Success Response**
	* **Code**: 200

* **Error Response**
	* **Code**: 400

### Prove 
* **Purpose**

	Generate a proof of data ownership.
		
		
* **URL**
	
	`/prove/:challenge/:txId/:type/:userId`
		
* **Method**

	`GET`


* **URL Params**

	**Required**:

	* `challenge=[alphanumeric]` 
	* `txId=[hexadecimal]` 
	* `type=[composition|license|recording|right]` 
	* `userId=[hexadecimal]`

* **Success Response**
	* **Code**: 200
			
* **Error Response**
	* **Code**: 400

### Release
* **Purpose**
	
	Persist metadata for a sound recording to the database.

* **URL**

	`/release`
		
	 
* **Method**

	`POST`
		
* **Data Params**
	```javascript
	u: {
		// Required
		artistIds: [array hexadecimal],
		compositionId: [hexadecimal],
		recording: [audio blob],

		// Required if artists aren't composition right-holders
		licenseId: [hexadecimal],

		// Required if multiple artists
		splits: [array],
		signatures: [array base58],

		// Optional
		duration: [alphanumeric],
		isrcCode: [alphanumeric & special characters],
		recordLabelId: [hexadecimal],
		url: [url]
	}
	```
		
* **Success Response**

	* **Code**: 200
	
		**Example**:
		```javascript 
		{
			"@context": "<context placeholder>",
			"@type": "MusicRecording",
			"byArtist": [
				{
					"@id": "<artistId1>"
				},
				{
					"@id": "<artistId2>"
				}
			],
			"duration": "<duration>",	// ex. "PT2M43S"
			"isrcCode": "<isrcCode>",   	// ex. "US-S1Z-99-00001"
			"recordLabel": {
				"@id": "<recordLabelId>"
			},
			"recordingOf": {
				"@id": "<compositionId>",
				"hasLicense": {
					"@id": "<licenseId>"
				}
			},
			"thresholdSignature": "<thresholdSignature>",	// ex. "cf:2:AQIB..."
			"url": "<url>"
		}
		```

* **Error Response**
	
	* **Code**: 400

	* **Code**: 404

		**Message**: Not logged in

### Register
* **Purpose**

	Persist a new user to the database.
	
* **URL**

	`/register`
	
* **Method**

	`POST`

* **Data Params**
	```javascript
	u: {
		// Required
		name: [string],
		password: [alphanumeric & special characters],
		sameAs: [url],
		type: [MusicGroup|Organization|Person],
		
		// Optional
		email: [email address],
		ipiNumber: [number],
		isniNumber: [alphanumeric],
		memberId: [array],
		pro: [string]
	}
	```

* **Success Response**
	* **Code**: 200
	
		**Example**:
		```javascript
		{
  			"privateKey": "<newPrivateKey>",
  			"publicKey": "<newPublicKey>"
			"userId": "<newUserId>",
		}
		```
* **Error Response**
	* **Code**: 400

### Right
* **Purpose**
	
	Persist a right (i.e. transfer of ownership shares) to the database. 

* **URL**

	`/right`
		
* **Method**

	`POST`
		
* **Data Params**
	```javascript
	u: {
		// Required
		percentShares: [integer],
		rightHolderId: [hexadecimal],
		rightToId: [hexadecimal],

		// Required if licenser isn't composer of composition/artist on recording
		prevRightId: [hexadecimal]
	}
	```

* **Success Response**

	* **Code**: 200
	
		**Example**:
		```javascript
		{
			"@context": "<context placeholder>",
			"@type": "Right",
			"rightHolder": [
				{
					"@id": "<rightHolderId1>"
				},
				{
					"@id": "<rightHolderId2>"
				}
			],
			"rightTo": {
				"@id": "<rightToId>"
			},
			"transfer": {
				"@id": "<newTransferId>"
			}
		}
		```
				

* **Error Response**
	
	* **Code**: 400

### Search
* **Purpose**
	
	Search for user profile, metadata, licenses, or rights.

* **URL**

	`/search/:type/:userId`
		
		
* **Method**

	`GET`
		
* **URL Params**

	**Required**:
		
	* `type=[composition|license|recording|right|user]`
	* `userId=[hexadecimal]`

	**Optional**:
	* `name=[string]`
		
* **Success Response**

	* **Code**: 200

* **Error Response**
	
	* **Code**: 400

### Verify 
* **Purpose**

	Verify a proof of data ownership.
		
		
* **URL**
	
	`/verify/:challenge/:signature/:txId/:type/:userId`
		
* **Method**

	`GET`


* **URL Params**
	
	**Required**:

	* `challenge=[base64]`
	* `signature=[base58]` 
	* `txId=[hexadecimal]` 
	* `type=[composition|license|recording|right]` 
	* `userId=[hexadecimal]`

* **Success Response**
	* **Code**: 200
				
* **Error Response**
	* **Code**: 400

	* **Code**: 404

		**Message**: Not logged in

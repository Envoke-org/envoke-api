## api

### Root

`http://localhost.com:8888/`

### Composition
* **Purpose**
	
	Persist metadata for a musical composition to the database.

* **URL**

	`/composition`

* **Method**

	`POST`

* **Data Params**
	```javascript
	u: {
		// Required
		composerIds: [array|hexadecimal],
		name: [string],
					
		// Optional
		hfaCode: [alphanumeric],
		inLanguage: [string],
		iswcCode: [alphanumeric & special characters],
		publisherId: [hexadecimal],
		splits: [array],
		thresholdSignature: [cf:number:base64],
		url: [url]
	}
	```   
		
* **Success Response**

	* **Code**: 200
	
		**Content**: 
		```javascript
		{ 
			"@context": "<context placeholder>",
			"@type": "MusicComposition",
			"composer": {
				"@id": "<composerId>"
			},
			"hfaCode": "<hfaCode>",		// ex. "B3107S"
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
		licenseForIds: [array],
		licenseHolderIds: [array],
		licenserId: [hexadecimal],
		validFrom: [date],		// ISO 8601
		validTo: [date],		// ...

		// Optional
		rightIds: [array]
	}
	```
	
* **Success Response**

	* **Code**: 200
	
		**Content**:
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
			"validThrough": "<validTo>"	// ex. "2024-01-01"
		}
		```

* **Error Response**
	
	* **Code**: 400

### Prove 
* **Purpose**

	Generate a proof of data ownership.
		
		
* **URL**
	
	`/prove?key=value&...`
		
* **Method**

	`GET`


* **URL Params**

	**Required**:

	* `challenge=[base64]` 
	* `dataId=[hexadecimal]` 
	* `type=[composition|license|recording|right]` 
	* `userId=[hexadecimal]`

* **Success Response**
	* **Code**: 200
			
* **Error Response**
	* **Code**: 400

### Recording
* **Purpose**
	
	Persist metadata for a sound recording to the database.

* **URL**

	`/recording`
		
	 
* **Method**

	`POST`
		
* **Data Params**
	```javascript
	u: {
		// Required
		artistIds: [array],
		compositionId: [hexadecimal],
		recording: [audio blob],

		// Optional
		duration: [alphanumeric],
		isrcCode: [alphanumeric & special characters],
		licenseId: [hexadecimal],
		recordLabelId: [hexadecimal],
		splits: [array],
		thresholdSignature: [cf:number:base64],
		url: [url]
	}
	```
		
* **Success Response**

	* **Code**: 200
	
		**Content**:
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
		prevTransferId: [hexadecimal],
		rightHolderId: [hexadecimal],
		rightToId: [hexadecimal]
	}
	```

* **Success Response**

	* **Code**: 200
	
		**Content**:
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

	`/search?key=value&...`
		
		
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
	
	`/verify?key=value&...`
		
* **Method**

	`GET`


* **URL Params**

	**Required**:

	* `challenge=[base64]`
	* `dataId=[hexadecimal]` 
	* `signature=[base58]` 
	* `type=[composition|license|recording|right]` 
	* `userId=[hexadecimal]`

* **Success Response**
	* **Code**: 200
				
* **Error Response**
	* **Code**: 400


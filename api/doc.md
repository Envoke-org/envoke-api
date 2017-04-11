## api

### Root

`http://localhost.com:8888/`


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
  // REQUIRED
  licenseForIds: [array hexadecimal],
  licenseHolderIds: [array hexadecimal],
  licenserId: [hexadecimal],
  validFrom: [date],
  validThrough: [date],

  // REQUIRED if licenser is not composer/publisher of composition(s) or artist/label on recording(s)
  rightIds: [array hexadecimal]
}
```
	
* **Success Response**

	* **Code**: 200
  
      **Content**: `txId=[hexadecimal]`

* **Error Response**
	
	* **Code**: 400

### Prove 
* **Purpose**

	Generate a proof of data ownership.
		
		
* **URL**
	
	`/prove/:challenge/:txId/:type/:userId`
		
* **Method**

	`GET`


* **Named Params**

	**Required**:
  
	* `challenge=[alphanumeric]` 
	* `txId=[hexadecimal]` 
	* `type=[composition|license|recording|right]` 
	* `userId=[hexadecimal]`

* **Success Response**
	* **Code**: 200
  
      **Content**: `signature=[base58]`
			
* **Error Response**

	* **Code**: 400
    
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
		// REQUIRED
		composerIds: [array hexadecimal],
		name: [string],

		// REQUIRED if publisher(s) or multiple composers
		signatures: [array base58],
		splits: [array integer],
					
		// OPTIONAL
		inLanguage: [string],
		iswcCode: [alphanumeric & special characters],
		publisherIds: [array hexadecimal],
		url: [url]
	}
	``` 
		
* **Success Response**

	* **Code**: 200
  
      **Content**: `txId=[hexadecimal]`

* **Error Response**
	
	* **Code**: 400

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
		// REQUIRED
		name: [string],
		password: [alphanumeric & special characters],
		sameAs: [url],
		type: [MusicGroup|Organization|Person],
		
		// OPTIONAL
		email: [email address],
		ipiNumber: [number],
		isniNumber: [alphanumeric],
		memberIds: [array hexadecimal],
		pro: [string]
	}
	```

* **Success Response**

	* **Code**: 200
  
      **Content**:
      ```javascript
      u: {
            privateKey: [base58],
            publicKey:  [base58],
            userId: [hexadecimal]
      }
      ```

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
		// REQUIRED
		artistIds: [array hexadecimal],
		compositionId: [hexadecimal],

		// REQUIRED if artists/labels aren't composers/publishers of composition
		licenseIds: [array hexadecimal],
		rightIds: [array hexadecimal],

		// REQUIRED if label(s) or multiple artists
		splits: [array integer],
		signatures: [array base58],

		// OPTIONAL
		duration: [alphanumeric],
		isrcCode: [alphanumeric & special characters],
		recordLabelIds: [array hexadecimal],
		url: [url]
	}
	```
		
* **Success Response**

	* **Code**: 200
  
      **Content**: `txId=[hexadecimal]`


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
		// REQUIRED
		percentShares: [integer],
		recipientId: [hexadecimal],
		rightToId: [hexadecimal],

		// REQUIRED if licenser isn't composer/publisher of composition or artist/label on recording
		previousRightId: [hexadecimal]
	}
	```

* **Success Response**

	* **Code**: 200
				
       **Content**: `txId=[hexadecimal]`

* **Error Response**
	
	* **Code**: 400

### Search
* **Purpose**
	
	Search for user profile, metadata, licenses, or rights.

* **URL**

	`/search/:type/:userId`
		
* **Method**

	`GET`
		
* **Named Params**

	**Required**:
		
	* `type=[composition|license|recording|right|user]`
	* `userId=[hexadecimal]`
		
* **Success Response**

	* **Code**: 200
  
      **Content**: see `spec` for data models

* **Error Response**
	
	* **Code**: 400
  
### Search Name
* **Purpose**
	
	Search for user compositions/recordings by name.

* **URL**

	`/search/:type/:userId/:name`
		
* **Method**

	`GET`
		
* **Named Params**

	**Required**:
		
	* `type=[composition|recording]`
	* `userId=[hexadecimal]`
  	* `name=[alphanumeric]`
		
* **Success Response**

	* **Code**: 200
  
      **Content**: see `spec` for data models

* **Error Response**
	
	* **Code**: 400
    
### Sign Composition
* **Purpose**

  Generate a signature of a composition.
  
* **URL**

  `/sign/composition`
  
* **Method**

  `POST`
  
 
* **Data Params**
  ```javascript
    u: {
      // REQUIRED
      composerIds: [array hexadecimal],
      name: [string],

      // REQUIRED if publisher(s) or multiple composers
      splits: [array integer],

      // OPTIONAL
      inLanguage: [string],
      iswcCode: [alphanumeric & special characters],
      publisherIds: [array hexadecimal],
      url: [url]
    }
    ```
  
* **Success Response**

	* **Code**: 200
  
       **Content**: `signature=[base58]` 

* **Error Response**
	
	* **Code**: 400
    
### Sign Recording
* **Purpose**

  Generate a signature of a recording.
  
* **URL**

  `/sign/recording`
  
* **Method**

  `POST`
  
 
* **Data Params**
  ```javascript
	u: {
		// REQUIRED
		artistIds: [array hexadecimal],
		compositionId: [hexadecimal],

		// REQUIRED if artists/labels aren't composers/publishers of composition
		licenseIds: [array hexadecimal],
		rightIds: [array hexadecimal],

		// REQUIRED if label(s) or multiple artists
		splits: [array],

		// OPTIONAL
		duration: [alphanumeric],
		isrcCode: [alphanumeric & special characters],
		recordLabelIds: [array hexadecimal],
		url: [url]
	}
	```
  
* **Success Response**

	* **Code**: 200
  
       **Content**: `signature=[base58]` 

* **Error Response**
	
	* **Code**: 400
 

### Verify 
* **Purpose**

	Verify a proof of data ownership.
		
		
* **URL**
	
	`/verify/:challenge/:signature/:txId/:type/:userId`
		
* **Method**

	`GET`


* **Named Params**
	
	**Required**:

	* `challenge=[alphanumeric]`
	* `signature=[base58]` 
	* `txId=[hexadecimal]` 
	* `type=[composition|license|recording|right]` 
	* `userId=[hexadecimal]`

* **Success Response**
	* **Code**: 200
				
* **Error Response**
	* **Code**: 400

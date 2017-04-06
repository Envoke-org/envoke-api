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
  // Required
  licenseForIds: [array hexadecimal],
  licenseHolderIds: [array hexadecimal],
  licenserId: [hexadecimal],
  validFrom: [date],
  validThrough: [date],

  // Required if licenser is not composer/artist of work(s)
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
		// Required
		name: [string],
		password: [alphanumeric & special characters],
		sameAs: [url],
		type: [MusicGroup|Organization|Person],
		
		// Optional
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
		// Required
		artistIds: [array hexadecimal],
		compositionId: [hexadecimal],

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
		// Required
		percentShares: [integer],
		recipientId: [hexadecimal],
		rightToId: [hexadecimal],

		// Required if licenser isn't composer/artist of work
		prevRightId: [hexadecimal]
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

  Generate a composer signature of a composition.
  
* **URL**

  `/sign/composition`
  
* **Method**

  `POST`
  
 
* **Data Params**
  ```javascript
    u: {
      // Required
      composerIds: [array hexadecimal],
      name: [string],

      // Required if multiple composers 
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
  
       **Content**: `signature=[base58]` 

* **Error Response**
	
	* **Code**: 400
    
### Sign Recording
* **Purpose**

  Generate an artist signature of a recording.
  
* **URL**

  `/sign/recording`
  
* **Method**

  `POST`
  
 
* **Data Params**
  ```javascript
	u: {
		// Required
		artistIds: [array hexadecimal],
		compositionId: [hexadecimal],

		// Required if artists aren't composition right-holders
		licenseId: [hexadecimal],

		// Required if multiple artists
		splits: [array],

		// Optional
		duration: [alphanumeric],
		isrcCode: [alphanumeric & special characters],
		recordLabelId: [hexadecimal],
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

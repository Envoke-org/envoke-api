ß## spec 

*Example scenarios with data models*

### Composition

Single composer

```javascript
{
  "@context": "<context placeholder>",
  "@type": "MusicComposition",
  "composer": [
    {
      "@id": "<composerId>"
    }
  ],
  "inLanguage": "EN",
  "name": "untitled",
  "url": "http://www.composition_url.com"
}
```

Multiple composers and publishers

```javascript
{
  "@context": "<context placeholder>",
  "@type": "MusicComposition",
  "composer": [
    {
      "@id": "<composerId>"
    },
    {
      "@id": "<composerId>"
    }
  ],
  "inLanguage": "EN",
  "iswcCode": "T-034.524.680-1",
  "name": "untitled",
  "publisher": [
    {
      "@id": "<publisherId>"
    },
    {
      "@id": "<publisherId>"
    }
  ]
}
```

### License

License for composition

```javascript
{
  "@context": "<context placeholder>",
  "@type": "License",
  "asset": [
    { 
      "@id": "<compositionId>"
    }
  ],
  "timeout": "<fulfillmentURI>"
}
```

License for composition and recording
```javascript
{
  "@context": "<context placeholder>",
  "@type": "License",
  "asset": [
    {
      "@id": "<compositionId>"
    },
    {
      "@id": "<recordingId>"
    }
  ],
  "timeout": "<fulfillmentURI>"
}
```

### Recording

Single artist (artist is composition right-holder)

```javascript
{
  "@context": "<context placeholder>",
  "@type": "MusicRecording",
  "byArtist": [
    {
      "@id": "<artistId>"
    }
  ],
  "duration": "PT2M43S",
  "recordingOf": {
    "@id": "<compositionId>"
  },
  "url": "http://www.recording.com"
}
```

Multiple artists with record label (artists and record label have license for composition)

```javascript
{
  "@context": "<context placeholder>",
  "@type": "MusicRecording",
  "byArtist": [
    {
      "hasLicense": {
        "@id": "<licenseId>"
      },
      "@id": "<artistId>"
    },
    {
      "hasLicense": {
        "@id": "<licenseId>"
      },
      "@id": "<artistId>"
    }
  ],
  "duration": "PT2M43S",
  "isrcCode": "US-S1Z-99-00001",
  "recordLabel": [
    {
      "hasLicense": {
        "@id": "<licenseId>"
      },
      "@id": "<recordLabelId>"
    }
  ],
  "recordingOf": {
    "@id": "<compositionId>"
  },
  "url": "http://www.recording.com"
}
```

### Right 

TRANSFER tx
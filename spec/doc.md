## spec 

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

License for composition with multiple license-holders (licenser is composer)

```javascript
{
  "@context": "<context placeholder>",
  "@type": "License",
  "licenseFor": [
    { 
      "@id": "<compositionId>"
    }
  ],
  "licenseHolder": [
    {
      "@id": "<licenseHolderId>"
    },
    {
      "@id": "<licenseHolderId>"
    }
  ],
  "licenser": {
    "@id": "<licenserId>"
  },
  "validFrom": "2020-01-01",
  "validThrough": "2024-01-01"
}
```

License for composition and recording with single license-holder (licenser has rights to composition and recording)
```javascript
{
  "@context": "<context placeholder>",
  "@type": "License",
  "licenseFor": [
    {
      "@id": "<compositionId>"
    },
    {
      "@id": "<recordingId>"
    }
  ],
  "licenseHolder": [
    {
      "@id": "<licenseHolderId>"
    }
  ],
  "licenser": {
    "hasRight": [
      {
        "@id": "<rightId>"
      },
      {
        "@id": "<rightId>"
      }
    ],
    "@id": "<licenserId>"
  },
  "validFrom": "2020-01-01",
  "validThrough": "2024-01-01"
}
```

### Recording

Single artist (artist composed composition)

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

Composition right with multiple right-holders
```javascript
{
  "@context": "<context placeholder>",
  "@type": "Right",
  "rightHolder": [
    {
      "@id": "<rightHolderId>"
    },
    {
      "@id": "<rightHolderId>"
    }
  ],
  "rightTo": {
    "@id": "<compositionId>"
  },
  "transfer": {
    "@id": "<transferId>"
  }
}
```
Recording right with single right-holder
```javascript
{
  "@context": "<context placeholder>",
  "@type": "Right",
  "rightHolder": [
    {
      "@id": "<rightHolderId>"
    }
  ],
  "rightTo": {
    "@id": "<recordingId>"
  },
  "transfer": {
    "@id": "<transferId>"
  }
}
```
package schema

import (
	jsonschema "github.com/xeipuuv/gojsonschema"

	. "github.com/zbo14/envoke/common"
	"github.com/zbo14/envoke/regex"
	"github.com/zbo14/envoke/spec"
)

const SCHEMA = "http://json-schema.org/draft-04/schema#"

func ValidateSchema(model Data, _type string) error {
	var schemaLoader jsonschema.JSONLoader
	modelLoader := jsonschema.NewGoLoader(model)
	switch _type {
	case "composition":
		schemaLoader = CompositionLoader
	case "license":
		schemaLoader = LicenseLoader
	case "recording":
		schemaLoader = RecordingLoader
	case "release":
		schemaLoader = ReleaseLoader
	case "right":
		schemaLoader = RightLoader
	case "user":
		schemaLoader = UserLoader
	default:
		return ErrorAppend(ErrInvalidType, _type)
	}
	result, err := jsonschema.Validate(schemaLoader, modelLoader)
	if err != nil {
		return err
	}
	if !result.Valid() {
		return Error(_type + " validation failed")
	}
	return nil
}

var link = Sprintf(`{
	"title": "Link",
	"type": "object",
	"properties": {
		"@id": {
			"type": "string",
			"pattern": "%s"
		}
	},
	"required": ["@id"]
}`, regex.ID)

var UserLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "User",
	"type": "object",
	"definitions": {
		"link": %s
	},
	"properties": {
		"@context": {
			"type": "string",
			"pattern": "^%s$"
		},
		"@type": {
			"type": "string",
			"pattern": "^MusicGroup|Organization|Person$"
		},
		"email": {
			"type": "string",
			"pattern": "%s"
		},
		"ipiNumber": {
			"type": "string",
			"pattern": "%s"
		},
		"isniNumber": {
			"type": "string",
			"pattern": "%s"
		},
		"member": {
			"type": "array",
			"items": {
				"$ref": "#/definitions/link"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"name": {
			"type": "string"
		},
		"pro": {
			"type": "string",
			"pattern": "%s"
		},
		"sameAs": {
			"type": "string"
		}
	},
	"required": ["@context", "@type", "name", "sameAs"]
}`, SCHEMA, link, spec.CONTEXT, regex.EMAIL, regex.IPI, regex.ISNI, regex.PRO))

var CompositionLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MusicComposition",
	"type": "object",
	"definitions": {
		"link": %s
	},
	"properties": {
		"@context": {
			"type": "string",
			"pattern": "^%s$"
		},
		"@type": {
			"type": "string",
			"pattern": "^MusicComposition$"
		},
		"composer": {
			"oneOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"type": "array",
					"items": {
						"$ref": "#/definitions/link"
					},	
					"minItems": 2,
					"uniqueItems": true
				}
			]
		},
		"hfaCode": {
			"type": "string",
			"pattern": "%s"
		},
		"inLanguage": {
			"type": "string",
			"pattern": "%s"
		},
		"iswcCode": {
			"type": "string",
			"pattern": "%s"
		},
		"name": {
			"type": "string"
		},
		"publisher": {
			"$ref": "#/definitions/link"
		},
		"thresholdSignature": {
			"type": "string",
			"pattern": "%s"
		},
		"url": {
			"type": "string"
		}
	},
	"oneOf": [
		{
			"properties": {
				"composer": {
					"type": "array"
				}
			},
			"required": ["thresholdSignature"]
		},
		{
			"properties": {
				"composer": {
					"$ref": "#/definitions/link"
				}
			},
			"not": {
				"required": ["thresholdSignature"]
			}
		}
	],
	"required": ["@context", "@type", "composer", "name"]
}`, SCHEMA, link, spec.CONTEXT, regex.HFA, regex.LANGUAGE, regex.ISWC, regex.FULFILLMENT))

var RecordingLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema":  "%s",
	"title": "MusicRecording",
	"type": "object",
	"definitions": {
		"composition": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"hasLicense": {
							"$ref": "#/definitions/link"
						}
					}
				}
			]
		},
		"link": %s
	},
	"properties": {
		"@context": {
			"type": "string",
			"pattern": "^%s$"
		},
		"@type": {
			"type": "string",
			"pattern": "^MusicRecording$"
		},
		"byArtist": {
			"oneOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"type": "array",
					"items": {
						"$ref": "#/definitions/link"
					},
					"minItems": 2,
					"uniqueItems": true
				}
			]
		},
		"duration": {
			"type": "string"			
		},
		"hasLicense": {
			"$ref": "#/definitions/link"
		},
		"isrcCode": {
			"type": "string",
			"pattern": "%s"
		},
		"recordingOf": {
			"$ref": "#/definitions/composition"
		},
		"recordLabel": {
			"$ref": "#/definitions/link"
		},
		"thresholdSignature": {
			"type": "string",
			"pattern": "%s"
		},
		"url": {
			"type": "string"
		}
	},
	"oneOf": [
		{
			"properties": {
				"byArtist": {
					"type": "array"
				}
			},
			"required": ["thresholdSignature"]
		},
		{
			"properties": {
				"byArtist": {
					"$ref": "#/definitions/link"
				}
			},
			"not": {
				"required": ["thresholdSignature"]
			}
		}
	],
	"required": ["@context", "@type", "byArtist", "recordingOf"]
}`, SCHEMA, link, spec.CONTEXT, regex.ISRC, regex.FULFILLMENT))

var ReleaseLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema":  "%s",
	"title": "MusicRelease",
	"type": "object",
	"definitions": {
		"recording": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"hasRight": {
							"$ref": "#/definitions/link"
						}
					},
					"required": ["hasRight"]
				}
			]
		},
		"link": %s
	},
	"properties": {
		"@context": {
			"type": "string",
			"pattern": "^%s$"
		},
		"@type": {
			"type": "string",
			"pattern": "^MusicRelease$"
		},
		"name": {
			"type": "string"
		},
		"recording": {
			"oneOf": [
				{
					"$ref": "#/definitions/recording"
				},	
				{
					"type": "array",
					"items": {
						"$ref": "#/definitions/recording"
					},
					"minItems": 2,
					"uniqueItems": true
				}
			]
		},
		"recordLabel": {
			"$ref": "#/definitions/link"
		},
		"sameAs": {
			"type": "string"
		}
	},
	"required": ["@context", "@type", "name", "recording", "recordLabel"]
}`, SCHEMA, link, spec.CONTEXT))

var RightLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "Right",
	"type": "object",
	"definitions": {
		"link": %s
	},
	"properties": {
		"@context": {
			"type": "string",
			"pattern": "^%s$"
		},
		"@type": {
			"type": "string",
			"pattern": "^Right$"
		},
		"rightHolder": {
			"type": "array",
			"items": {
				"$ref": "#/definitions/link"
			},
			"minItems": 1,
			"maxItems": 2,
			"uniqueItems": true
		},
		"rightTo": {
			"$ref": "#/definitions/link"
		},
		"transfer": {
			"$ref": "#/definitions/link"
		}
	},
	"required": ["@context", "@type", "rightHolder", "rightTo", "transfer"]
}`, SCHEMA, link, spec.CONTEXT))

var LicenseLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "License",
	"type": "object",
	"definitions": {
		"licenseFor": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"hasRight": {
							"$ref": "#/definitions/link"
						}
					}
				}
			]
		},
		"link": %s
	},
	"properties": {
		"@context": {
			"type": "string",
			"pattern": "^%s$"
		},
		"@type": {
			"type": "string",
			"pattern": "^License$"
		},
		"licenseFor": {
			"type": "array",
			"items": {
				"$ref": "#/definitions/licenseFor"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"licenseHolder": {
			"type": "array",
			"items": {
				"$ref": "#/definitions/link"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"licenser": {
			"$ref": "#/definitions/link"
		},
		"validFrom": {
			"type": "string",
			"pattern": "%s"
		},
		"validThrough": {
			"type": "string",
			"pattern": "%s"
		}
	},
	"required": ["@context", "@type", "licenseFor", "licenseHolder", "licenser", "validFrom", "validThrough"]
}`, SCHEMA, link, spec.CONTEXT, regex.DATE, regex.DATE))

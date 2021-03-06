package schema

import (
	jsonschema "github.com/xeipuuv/gojsonschema"

	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/regex"
	"github.com/Envoke-org/envoke-api/spec"
)

const SCHEMA = "http://json-schema.org/draft-04/schema#"

func ValidateSchema(data Data, _type string) error {
	var schemaLoader jsonschema.JSONLoader
	dataLoader := jsonschema.NewGoLoader(data)
	switch _type {
	case "composition":
		schemaLoader = CompositionLoader
	case "license":
		schemaLoader = LicenseLoader
	case "recording":
		schemaLoader = RecordingLoader
	case "right":
		schemaLoader = RightLoader
	case "user":
		schemaLoader = UserLoader
	default:
		return ErrorAppend(ErrInvalidType, _type)
	}
	result, err := jsonschema.Validate(schemaLoader, dataLoader)
	if err != nil {
		return err
	}
	if !result.Valid() {
		// PrintJSON(data)
		return Errorf("%v", result.Errors())
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
			"type": "array",
			"items": {
				"$ref": "#/definitions/link"
			},	
			"minItems": 1,
			"uniqueItems": true
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
			"type": "array",
			"items": {
				"$ref": "#/definitions/link"
			},	
			"minItems": 1,
			"uniqueItems": true
		},
		"url": {
			"type": "string"
		}
	},
	"required": ["@context", "@type", "composer", "name"]
}`, SCHEMA, link, spec.CONTEXT, regex.LANGUAGE, regex.ISWC))

var RecordingLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema":  "%s",
	"title": "MusicRecording",
	"type": "object",
	"definitions": {
		"link": %s,
		"party": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"hasLicense": {
							"$ref": "#/definitions/link"
						},
						"hasRight": {
							"$ref": "#/definitions/link"
						}
					}
				}
			]
		}
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
			"type": "array",
			"items": {
				"$ref": "#/definitions/party"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"duration": {
			"type": "string"			
		},
		"isrcCode": {
			"type": "string",
			"pattern": "%s"
		},
		"recordingOf": {
			"$ref": "#/definitions/link"
		},
		"recordLabel": {
			"type": "array",
			"items": {
				"$ref": "#/definitions/party"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"url": {
			"type": "string"
		}
	},
	"required": ["@context", "@type", "byArtist", "recordingOf"]
}`, SCHEMA, link, spec.CONTEXT, regex.ISRC))

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
				"$ref": "#/definitions/link"
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
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"hasRight": {
							"type": "array",
							"items": {
								"$ref": "#/definitions/link"
							},
							"minItems": 1,
							"uniqueItems": true
						}
					}
				}
			]
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

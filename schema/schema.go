package schema

import (
	jsonschema "github.com/xeipuuv/gojsonschema"

	. "github.com/zbo14/envoke/common"
	regex "github.com/zbo14/envoke/regex"
	"github.com/zbo14/envoke/spec"
)

const SCHEMA = "http://json-schema.org/draft-04/schema#"

func ValidateSchema(model Data, _type string) error {
	var schemaLoader jsonschema.JSONLoader
	modelLoader := jsonschema.NewGoLoader(model)
	switch _type {
	case "party":
		schemaLoader = PartyLoader
	case "composition":
		schemaLoader = CompositionLoader
	case "composition_right":
		schemaLoader = CompositionRightLoader
	case "master_license":
		schemaLoader = MasterLicenseLoader
	case "mechanical_license":
		schemaLoader = MechanicalLicenseLoader
	case "publication":
		schemaLoader = PublicationLoader
	case "recording":
		schemaLoader = RecordingLoader
	case "recording_right":
		schemaLoader = RecordingRightLoader
	case "release":
		schemaLoader = ReleaseLoader
	default:
		return ErrorAppend(ErrInvalidType, _type)
	}
	result, err := jsonschema.Validate(schemaLoader, modelLoader)
	if err != nil {
		return err
	}
	if !result.Valid() {
		Println(result.Errors())
		PrintJSON(model)
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

var PartyLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "Party",
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
	"required": ["@context", "@type", "name"]
}`, SCHEMA, link, spec.CONTEXT, regex.EMAIL, regex.IPI, regex.ISNI, regex.PRO))

var CompositionLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MusicComposition",
	"type": "object",
	"definitions": {
		"composer": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"role": {
							"type": "string" 
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
			"pattern": "^MusicComposition$"
		},
		"composer": {
			"oneOf": [
				{
					"$ref": "#/definitions/composer"
				},
				{
					"type": "array",
					"items": {
						"$ref": "#/definitions/composer"
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
		"sameAs": {
			"type": "string"
		},
		"uri": {
			"type": "string",
			"pattern": "%s"
		}
	},
	"oneOf": [
		{
			"properties": {
				"composer": {
					"type": "array"
				}
			},
			"required": ["uri"]
		},
		{
			"properties": {
				"composer": {
					"$ref": "#/definitions/composer"
				}
			},
			"not": {
				"required": ["uri"]
			}
		}
	],
	"required": ["@context", "@type", "composer", "name"]
}`, SCHEMA, link, spec.CONTEXT, regex.HFA, regex.LANGUAGE, regex.ISWC, regex.FULFILLMENT))

var PublicationLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MusicPublication",
	"type": "object",
	"definitions": {
		"composition": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"right": {
							"$ref": "#/definitions/link"
						}
					},
					"required": ["right"]
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
			"pattern": "^MusicPublication$"
		},
		"name": {
			"type": "string"
		},
		"composition": {
			"oneOf": [
				{
					"$ref": "#/definitions/composition"
				},
				{
					"type": "array",
					"items": {
						"$ref": "#/definitions/composition"
					},
					"minItems": 2,
					"uniqueItems": true
				}
			]
		},
		"publisher": {
			"$ref": "#/definitions/link"
		},
		"sameAs": {
			"type": "string"
		}
	},
	"required": ["@context", "@type", "composition", "name", "publisher"]
}`, SCHEMA, link, spec.CONTEXT))

var RecordingLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema":  "%s",
	"title": "MusicRecording",
	"type": "object",
	"definitions": {
		"artist": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"mechanicalLicense": {
							"$ref": "#/definitions/link"
						},
						"role": {
							"type": "string" 
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
					"$ref": "#/definitions/artist"
				},
				{
					"type": "array",
					"items": {
						"$ref": "#/definitions/artist"
					},
					"minItems": 2,
					"uniqueItems": true
				}
			]
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
		"sameAs": {
			"type": "string"
		},
		"uri": {
			"type": "string",
			"pattern": "%s"
		}
	},
	"oneOf": [
		{
			"properties": {
				"byArtist": {
					"type": "array"
				}
			},
			"required": ["uri"]
		},
		{
			"properties": {
				"byArtist": {
					"$ref": "#/definitions/artist"
				}
			},
			"not": {
				"required": ["uri"]
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
						"right": {
							"$ref": "#/definitions/link"
						}
					},
					"required": ["right"]
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

var CompositionRightLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "CompositionRight",
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
			"pattern": "^CompositionRight$"
		},
		"composition": {
			"$ref": "#/definitions/link"
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
		"transfer": {
			"$ref": "#/definitions/link"
		}
	},
	"required": ["@context", "@type", "composition", "rightHolder", "transfer"]
}`, SCHEMA, link, spec.CONTEXT))

var RecordingRightLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "RecordingRight",
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
			"pattern": "^RecordingRight$"
		},
		"recording": {
			"$ref": "#/definitions/link"
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
		"transfer": {
			"$ref": "#/definitions/link"
		}
	},
	"required": ["@context", "@type", "recording", "rightHolder", "transfer"]
}`, SCHEMA, link, spec.CONTEXT))

var MechanicalLicenseLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MechanicalLicense",
	"type": "object",
	"definitions": {
		"composition": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"right": {
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
			"pattern": "^MechanicalLicense$"
		},
		"composition": {
			"type": "array",
			"items": {
				"$ref": "#/definitions/composition"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"licenseHolder": {
			"$ref": "#/definitions/link"
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
	"required": ["@context", "@type", "composition", "licenseHolder", "licenser", "validFrom", "validThrough"]
}`, SCHEMA, link, spec.CONTEXT, regex.DATE, regex.DATE))

var MasterLicenseLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MasterLicense",
	"type": "object",
	"definitions": {
		"recording": {
			"allOf": [
				{
					"$ref": "#/definitions/link"
				},
				{
					"properties": {
						"right": {
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
			"pattern": "^MasterLicense$"
		},
		"licenseHolder": {
			"$ref": "#/definitions/link"
		},
		"licenser": {
			"$ref": "#/definitions/link"
		},
		"recording": {
			"type": "array",
			"items": {
				"$ref": "#/definitions/recording"
			},
			"minItems": 1,
			"uniqueItems": true
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
	"required": ["@context", "@type", "licenseHolder", "licenser", "recording", "validFrom", "validThrough"]
}`, SCHEMA, link, spec.CONTEXT, regex.DATE, regex.DATE))

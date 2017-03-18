package schema

import (
	jsonschema "github.com/xeipuuv/gojsonschema"

	. "github.com/zbo14/envoke/common"
	regex "github.com/zbo14/envoke/regex"
	"github.com/zbo14/envoke/spec"
)

const SCHEMA = "http://json-schema.org/draft-04/schema#"

func ValidateModel(model Data, _type string) error {
	var schemaLoader jsonschema.JSONLoader
	modelLoader := jsonschema.NewGoLoader(model)
	switch _type {
	case "party":
		schemaLoader = PartyLoader
	case "collaboration":
		schemaLoader = CollaborationLoader
	case "composition":
		schemaLoader = CompositionLoader
	case "composition_right":
		schemaLoader = CompositionRightLoader
	case "composition_right_transfer":
		schemaLoader = CompositionRightTransferLoader
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
	case "recording_right_transfer":
		schemaLoader = RecordingRightTransferLoader
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

var itemList = Sprintf(`{
	"title": "ItemList",
	"type": "object",
	"definitions": {
		"link": %s
	},
	"properties": {
		"@type": {
			"type": "string",
			"pattern": "^ItemList$"
		},
		"itemListElement": {
			"type": "array",
			"items": {
				"@type": {
					"type": "string",
					"pattern": "^ListItem$"
				},
				"properties": {
					"item": {
						"$ref": "#/definitions/link"
					},
					"position": {
						"type": "integer"
					}
				},
				"required": ["@type", "item", "position"]
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"numberOfItems": {
			"type": "integer"
		}
	},
	"required": ["@type", "itemListElement", "numberOfItems"]
}`, link)

var CollaborationLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MusicCollaboration",
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
			"pattern": "^MusicCollaboration$"
		},
		"member": {
			"type": "array",
			"items": {
				"properties": {
					"@type": {
						"type": "string",
						"pattern": "^OrganizationRole$"
					},
					"member": {
						"$ref": "#/definitions/link"
					},
					"roleName": {
						"type": "string"
					},
					"split": {
						"type": "integer",
						"minimum": 0,
						"maximum": 100,
						"exclusiveMinimum": true,
						"exclusiveMaximum": true
					}
				},
				"required": ["@type", "member"]
			},
			"minItems": 2,
			"uniqueItems": true
		},
		"name": {
			"type": "string"
		}
	},
	"required": ["@context", "@type", "member"]
}`, SCHEMA, link, spec.CONTEXT))

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
		"collaboration": {
			"type": "boolean"
		},
		"composer": {
			"$ref": "#/definitions/link"
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
				"collaboration": {"enum": [true]}
			},
			"required": ["uri"]
		},
		{
			"properties": {
				"collaboration": {"enum": [false]}
			},
			"not": {
				"required": ["uri"]
			}
		}
	],
	"required": ["@context", "@type", "collaboration", "composer", "name"]
}`, SCHEMA, link, spec.CONTEXT, regex.HFA, regex.LANGUAGE, regex.ISWC, regex.FULFILLMENT))

var PublicationLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MusicPublication",
	"type": "object",
	"definitions": {
		"itemList": %s,
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
		"composition": {
			"$ref": "#/definitions/itemList"
		},
		"compositionRight": {
			"$ref": "#/definitions/itemList"
		},
		"name": {
			"type": "string"
		},
		"publisher": {
			"$ref": "#/definitions/link"
		},
		"sameAs": {
			"type": "string"
		}
	},
	"required": ["@context", "@type", "composition", "compositionRight", "name", "publisher"]
}`, SCHEMA, itemList, link, spec.CONTEXT))

var RecordingLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema":  "%s",
	"title": "MusicRecording",
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
			"pattern": "^MusicRecording$"
		},
		"byArtist": {
			"$ref": "#/definitions/link"
		},
		"collaboration": {
			"type": "boolean"
		},
		"compositionRight": {
			"$ref": "#/definitions/link"
		},
		"duration": {
			"type": "string"			
		},
		"isrcCode": {
			"type": "string",
			"pattern": "%s"
		},
		"publication": {
			"$ref": "#/definitions/link"
		},
		"recordingOf": {
			"$ref": "#/definitions/link"
		},
		"recordLabel": {
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
	"dependencies": {
		"compositionRight": ["publication"],
		"publication": ["compositionRight"]
	},
	"not": {
		"allOf": [
			{
				"required": ["compositionRight"]
			},
			{
				"required": ["mechanicalLicense"]
			}
		]
	},
	"oneOf": [
		{
			"properties": {
				"collaboration": {"enum": [true]}
			},
			"required": ["uri"]
		},
		{
			"properties": {
				"collaboration": {"enum": [false]}
			},
			"not": {
				"required": ["uri"]
			}
		}
	],
	"required": ["@context", "@type", "byArtist", "collaboration", "recordingOf"]
}`, SCHEMA, link, spec.CONTEXT, regex.ISRC, regex.FULFILLMENT))

var ReleaseLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema":  "%s",
	"title": "MusicRelease",
	"type": "object",
	"definitions": {
		"itemList": %s,
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
			"$ref": "#/definitions/itemList"
		},
		"recordingRight": {
			"$ref": "#/definitions/itemList"
		},
		"recordLabel": {
			"$ref": "#/definitions/link"
		},
		"sameAs": {
			"type": "string"
		}
	},
	"required": ["@context", "@type", "name", "recording", "recordingRight", "recordLabel"]
}`, SCHEMA, itemList, link, spec.CONTEXT))

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
		"recipient": {
			"$ref": "#/definitions/link"
		},
		"sender": {
			"$ref": "#/definitions/link"
		},
		"territory": {
			"type": "array",
			"items": {
				"type": "string",
				"pattern": "%s"
			}
		},
		"uri": {
			"type": "string",
			"pattern": "%s"
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
	"required": ["@context", "@type", "recipient", "sender", "territory", "validFrom", "validThrough"]
}`, SCHEMA, link, spec.CONTEXT, regex.TERRITORY, regex.FULFILLMENT, regex.DATE, regex.DATE))

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
		"recipient": {
			"$ref": "#/definitions/link"
		},
		"sender": {
			"$ref": "#/definitions/link"
		},
		"territory": {
			"type": "array",
			"items": {
				"type": "string",
				"pattern": "%s"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"uri": {
			"type": "string",
			"pattern": "%s"
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
	"required": ["@context", "@type", "recipient", "sender", "territory", "validFrom", "validThrough"]
}`, SCHEMA, link, spec.CONTEXT, regex.TERRITORY, regex.FULFILLMENT, regex.DATE, regex.DATE))

var CompositionRightTransferLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "CompositionRightTransfer",
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
			"pattern": "^CompositionRightTransfer$"
		},
		"compositionRight": {
			"$ref": "#/definitions/link"
		},
		"publication": {
			"$ref": "#/definitions/link"
		},
		"recipient": {
			"$ref": "#/definitions/link"
		},
		"sender": {
			"$ref": "#/definitions/link"
		},
		"tx": {
			"$ref": "#/definitions/link"
		}
	},
	"required": ["@context", "@type", "compositionRight", "publication", "recipient", "sender", "tx"]
}`, SCHEMA, link, spec.CONTEXT))

var RecordingRightTransferLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "RecordingRightTransfer",
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
			"pattern": "^RecordingRightTransfer$"
		},
		"recipient": {
			"$ref": "#/definitions/link"
		},
		"recordingRight": {
			"$ref": "#/definitions/link"
		},
		"release": {
			"$ref": "#/definitions/link"
		},
		"sender": {
			"$ref": "#/definitions/link"
		},
		"tx": {
			"$ref": "#/definitions/link"
		}
	},
	"required": ["@context", "@type", "recipient", "recordingRight", "release", "sender", "tx"]
}`, SCHEMA, link, spec.CONTEXT))

var MechanicalLicenseLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MechanicalLicense",
	"type": "object",
	"definitions": {
		"itemList": %s,
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
			"$ref": "#/definitions/itemList"
		},
		"compositionRight": {
			"$ref": "#/definitions/link"
		},
		"compositionRightTransfer": {
			"$ref": "#/definitions/link"
		},
		"publication": {
			"$ref": "#/definitions/link"
		},
		"recipient": {
			"$ref": "#/definitions/link"
		},
		"sender": {
			"$ref": "#/definitions/link"
		},
		"territory": {
			"type": "array",
			"items": {
				"type": "string",
				"pattern": "%s"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"usage": {
			"oneOf": [
				{
					"type": "array",
					"items": {
						"type": "string"
					},
					"minItems": 1,
					"uniqueItems": true
				},
				{
					"type": "null"
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
	"anyOf": [
		{
			"required": ["composition"]
		},
		{
			"required": ["publication"]
		}
	],
	"dependencies": {
		"publication": {
			"oneOf": [
				{
					"required": ["compositionRight"]
				},
				{
					"required": ["compositionRightTransfer"]
				}
			]
		}
	},
	"required": ["@context", "@type", "recipient", "sender", "territory", "usage", "validFrom", "validThrough"]
}`, SCHEMA, itemList, link, spec.CONTEXT, regex.TERRITORY, regex.DATE, regex.DATE))

var MasterLicenseLoader = jsonschema.NewStringLoader(Sprintf(`{
	"$schema": "%s",
	"title": "MasterLicense",
	"type": "object",
	"definitions": {
		"itemList": %s,
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
		"recipient": {
			"$ref": "#/definitions/link"
		},
		"recording": {
			"$ref": "#/definitions/itemList"
		},
		"recordingRight": {
			"$ref": "#/definitions/link"
		},
		"recordingRightTransfer": {
			"$ref": "#/definitions/link"
		},
		"release": {
			"$ref": "#/definitions/link"
		},
		"sender": {
			"$ref": "#/definitions/link"
		},
		"territory": {
			"type": "array",
			"items": {
				"type": "string",
				"pattern": "%s"
			},
			"minItems": 1,
			"uniqueItems": true
		},
		"usage": {
			"oneOf": [
				{
					"type": "array",
					"items": {
						"type": "string"
					},
					"minItems": 1,
					"uniqueItems": true
				},
				{
					"type": "null"
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
	"anyOf": [
		{
			"required": ["recording"]
		},
		{
			"required": ["release"]
		}
	],
	"dependencies": {
		"release": {
			"oneOf": [
				{
					"required": ["recordingRight"]
				},
				{
					"required": ["recordingRightTransfer"]
				}
			]
		}
	},
	"required": ["@context", "@type", "recipient", "sender", "territory", "usage", "validFrom", "validThrough"]
}`, SCHEMA, itemList, link, spec.CONTEXT, regex.TERRITORY, regex.DATE, regex.DATE))

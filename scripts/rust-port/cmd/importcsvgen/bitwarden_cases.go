package main

import "strings"

// bitwardenCases freezes Bitwarden JSON decoding (encoding/json semantics:
// null, wrong-type, case-insensitive keys, duplicate keys, malformed input)
// and the importer dispatch for the generic json/yaml format names. The
// expected values are produced by running the production Go importer; nothing
// here is hand-written output.
func bitwardenCases() []csvCase {
	bw := func(name, input string) csvCase {
		return csvCase{Name: "bw_" + name, Format: "bitwarden", Input: input}
	}
	nested := func(depth int) string {
		return strings.Repeat("[", depth) + strings.Repeat("]", depth)
	}
	return []csvCase{
		// Generic JSON/YAML names have no importer at the base revision.
		{Name: "generic_json_unsupported", Format: "json", Input: `{"items":[]}`},
		{Name: "generic_yaml_unsupported", Format: "yaml", Input: "items: []\n"},
		{Name: "generic_yml_unsupported", Format: "yml", Input: "items: []\n"},
		{Name: "format_name_is_case_sensitive", Format: "Bitwarden", Input: `{"items":[]}`},
		{Name: "format_name_is_not_trimmed", Format: "bitwarden ", Input: `{"items":[]}`},
		{Name: "format_name_empty", Format: "", Input: `{"items":[]}`},

		// Malformed JSON: syntax diagnostics.
		bw("syntax_empty_input", ``),
		bw("syntax_whitespace_only", " \n\t "),
		bw("syntax_truncated_array", `{"items":[`),
		bw("syntax_truncated_literal", `{"items":tru`),
		bw("syntax_truncated_string", `{"items":[{"name":"abc`),
		bw("syntax_truncated_number", `-`),
		bw("syntax_bad_literal", `{"items":nul}`),
		bw("syntax_bad_value_start", `{"items":}`),
		bw("syntax_missing_comma", `{"items":[] "folders":[]}`),
		bw("syntax_missing_colon", `{"items" []}`),
		bw("syntax_trailing_comma_array", `{"items":[{"type":1},]}`),
		bw("syntax_trailing_comma_object", `{"items":[],}`),
		bw("syntax_unquoted_key", `{items:[]}`),
		bw("syntax_single_quoted_key", `{'items':[]}`),
		bw("syntax_bad_escape", `{"items":[{"name":"a\qb"}]}`),
		bw("syntax_bad_unicode_escape", `{"items":[{"name":"\u12g4"}]}`),
		bw("syntax_control_char_in_string", "{\"items\":[{\"name\":\"a\nb\"}]}"),
		bw("syntax_leading_zero_number", `{"items":[{"type":01}]}`),
		bw("syntax_dot_without_digit", `{"items":[{"type":1.}]}`),
		bw("syntax_exponent_without_digit", `{"items":[{"type":1e}]}`),
		bw("syntax_minus_without_digit", `{"items":[{"type":-}]}`),
		bw("syntax_bom_prefix", "\ufeff{\"items\":[]}"),
		bw("syntax_nbsp_prefix", "\u00a0{\"items\":[]}"),
		bw("syntax_garbage_after_valid_document", `{"items":[]}garbage`),
		bw("syntax_second_document_is_invalid", `{"items":[]} {broken`),
		bw("syntax_wins_over_earlier_type_error", `{"items":[{"name":5}],`),
		bw("syntax_max_depth_exceeded", nested(10001)),
		bw("syntax_max_depth_exceeded_inside_object", `{"x":`+nested(10000)+`}`),
		bw("syntax_max_depth_allowed_in_unknown_key", `{"x":`+nested(9999)+`,"items":[{"type":1,"name":"Deep"}]}`),

		// Top-level shapes.
		bw("top_array", `[]`),
		bw("top_string", `"x"`),
		bw("top_number", `5`),
		bw("top_true", `true`),
		bw("top_leading_zero_number", `01`),
		bw("top_object_trailing_literal", `{}x`),

		// Wrong types.
		bw("type_name_number", `{"items":[{"type":1,"name":5}]}`),
		bw("type_name_bool", `{"items":[{"type":1,"name":true}]}`),
		bw("type_name_object", `{"items":[{"type":1,"name":{"a":1}}]}`),
		bw("type_name_array", `{"items":[{"type":1,"name":["a"]}]}`),
		bw("type_kind_string", `{"items":[{"type":"1"}]}`),
		bw("type_kind_float", `{"items":[{"type":1.5}]}`),
		bw("type_kind_float_integral", `{"items":[{"type":1.0,"name":"A"}]}`),
		bw("type_kind_exponent", `{"items":[{"type":1e0,"name":"A"}]}`),
		bw("type_kind_overflow", `{"items":[{"type":99999999999999999999}]}`),
		bw("type_kind_negative_zero", `{"items":[{"type":-0,"name":"A"}]}`),
		bw("type_kind_bool", `{"items":[{"type":true}]}`),
		bw("type_kind_object", `{"items":[{"type":{}}]}`),
		bw("type_kind_unknown_values_skipped", `{"items":[{"type":-1,"name":"A"},{"type":0,"name":"B"},{"type":3,"name":"C"},{"type":4,"name":"D"},{"type":5,"name":"E"},{"type":99,"name":"F"}]}`),
		bw("type_wrong_inside_skipped_kind", `{"items":[{"type":3,"name":5}]}`),
		bw("type_items_object", `{"items":{}}`),
		bw("type_items_string", `{"items":"x"}`),
		bw("type_items_number", `{"items":1}`),
		bw("type_items_bool", `{"items":false}`),
		bw("type_items_element_string", `{"items":["x"]}`),
		bw("type_items_element_array", `{"items":[[]]}`),
		bw("type_items_element_number", `{"items":[1]}`),
		bw("type_folders_string", `{"folders":"x","items":[]}`),
		bw("type_folders_element_number", `{"folders":[1],"items":[]}`),
		bw("type_folder_id_number", `{"folders":[{"id":1,"name":"F"}],"items":[]}`),
		bw("type_folder_name_bool", `{"folders":[{"id":"f","name":true}],"items":[]}`),
		bw("type_folder_id_array", `{"folders":[{"id":["f"]}],"items":[]}`),
		bw("type_folder_id_null_is_empty", `{"folders":[{"id":null,"name":"Ignored"}],"items":[{"type":1,"name":"A"}]}`),
		bw("type_folderid_number", `{"items":[{"type":1,"name":"A","folderId":7}]}`),
		bw("type_notes_number", `{"items":[{"type":1,"notes":1}]}`),
		bw("type_login_array", `{"items":[{"type":1,"login":[]}]}`),
		bw("type_login_string", `{"items":[{"type":1,"login":"x"}]}`),
		bw("type_login_username_number", `{"items":[{"type":1,"login":{"username":1}}]}`),
		bw("type_login_password_bool", `{"items":[{"type":1,"login":{"password":false}}]}`),
		bw("type_login_totp_number", `{"items":[{"type":1,"login":{"totp":123456}}]}`),
		bw("type_login_uris_object", `{"items":[{"type":1,"login":{"uris":{}}}]}`),
		bw("type_login_uris_string", `{"items":[{"type":1,"login":{"uris":"https://x.test"}}]}`),
		bw("type_login_uri_element_string", `{"items":[{"type":1,"login":{"uris":["https://x.test"]}}]}`),
		bw("type_login_uri_number", `{"items":[{"type":1,"login":{"uris":[{"uri":1}]}}]}`),
		bw("type_fields_object", `{"items":[{"type":1,"fields":{}}]}`),
		bw("type_fields_string", `{"items":[{"type":1,"fields":"x"}]}`),
		bw("type_field_element_string", `{"items":[{"type":1,"fields":["x"]}]}`),
		bw("type_field_name_number", `{"items":[{"type":1,"fields":[{"name":1,"value":"v"}]}]}`),
		bw("type_field_value_number", `{"items":[{"type":1,"fields":[{"name":"n","value":1}]}]}`),
		bw("type_field_value_bool", `{"items":[{"type":1,"fields":[{"name":"n","value":true}]}]}`),
		bw("type_card_string", `{"items":[{"type":2,"card":"x"}]}`),
		bw("type_card_number_object", `{"items":[{"type":2,"card":{"number":4111}}]}`),
		bw("type_card_expmonth_number", `{"items":[{"type":2,"name":"Card","card":{"expMonth":12,"expYear":2030}}]}`),
		bw("type_card_cardholder_array", `{"items":[{"type":2,"card":{"cardholderName":[]}}]}`),
		bw("type_card_brand_number_unused_field", `{"items":[{"type":2,"card":{"brand":5}}]}`),
		bw("type_first_error_wins", `{"items":[{"type":1,"name":5,"notes":6},{"type":"x"}]}`),
		bw("type_first_error_wins_document_order", `{"items":[{"type":"x"}],"folders":"y"}`),
		bw("type_error_after_valid_items", `{"items":[{"type":1,"name":"A"},{"type":1,"name":[]}]}`),
		bw("type_unknown_key_wrong_type_ignored", `{"items":[{"type":1,"name":"A","extra":{"deep":[1,{"x":null}]}}],"unknown":5}`),

		// Nulls.
		bw("null_everything", `{"folders":null,"items":null}`),
		bw("null_item_fields", `{"items":[{"type":null,"name":null,"folderId":null,"notes":null,"login":null,"card":null,"fields":null}]}`),
		bw("null_login_fields", `{"items":[{"type":1,"name":"A","login":{"username":null,"password":null,"totp":null,"uris":null}}]}`),
		bw("null_items_element", `{"items":[null,{"type":1,"name":"A"}]}`),
		bw("null_uri_element", `{"items":[{"type":1,"name":"A","login":{"uris":[null,{"uri":"https://u.test"}]}}]}`),
		bw("null_uri_value", `{"items":[{"type":1,"name":"A","login":{"uris":[{"uri":null},{"uri":"https://u.test"}]}}]}`),
		bw("null_field_element", `{"items":[{"type":1,"name":"A","fields":[null,{"name":"n","value":"v"}]}]}`),
		bw("null_field_name_and_value", `{"items":[{"type":1,"name":"A","fields":[{"name":null,"value":"x"},{"name":"n","value":null}]}]}`),
		bw("null_card_fields", `{"items":[{"type":2,"name":"C","card":{"number":null,"cardholderName":null,"expMonth":null,"expYear":null,"code":null}}]}`),
		bw("null_folder_element", `{"folders":[null,{"id":"f","name":"F"}],"items":[{"type":1,"name":"A","folderId":"f"}]}`),
		bw("null_after_value_keeps_value", `{"items":[{"type":1,"name":"A","login":{"username":"u"},"login":null}]}`),
		bw("null_name_after_value_keeps_value", `{"items":[{"type":1,"name":"A","name":null}]}`),

		// Missing fields.
		bw("missing_items", `{}`),
		bw("missing_folders", `{"items":[{"type":1,"name":"A"}]}`),
		bw("missing_name_with_folder", `{"folders":[{"id":"f","name":"Folder"}],"items":[{"type":1,"folderId":"f"}]}`),
		bw("missing_name_without_folder", `{"items":[{"type":1}]}`),
		bw("missing_card_object", `{"items":[{"type":2,"name":"C"}]}`),
		bw("missing_login_object", `{"items":[{"type":1,"name":"L"}]}`),
		bw("missing_type", `{"items":[{"name":"NoType"}]}`),
		bw("missing_field_name_skipped", `{"items":[{"type":1,"name":"A","fields":[{"value":"orphan"},{"name":"","value":"empty"},{"name":"k"}]}]}`),
		bw("folder_unknown_id", `{"folders":[{"id":"f","name":"F"}],"items":[{"type":1,"name":"A","folderId":"other"}]}`),
		bw("folder_missing_name", `{"folders":[{"id":"f"}],"items":[{"type":1,"name":"A","folderId":"f"}]}`),
		bw("folder_duplicate_ids_last_wins", `{"folders":[{"id":"f","name":"One"},{"id":"f","name":"Two"}],"items":[{"type":1,"name":"A","folderId":"f"}]}`),
		bw("folder_slash_only_name", `{"folders":[{"id":"f","name":"/"}],"items":[{"type":1,"name":"A","folderId":"f"}]}`),
		bw("folder_name_normalized", `{"folders":[{"id":"f","name":" /Work Dir/ "}],"items":[{"type":1,"name":"A:b..c d","folderId":"f"}]}`),
		bw("folder_only_path", `{"folders":[{"id":"f","name":"Only"}],"items":[{"type":1,"folderId":"f","name":""}]}`),
		bw("folder_id_empty_item_folderid_empty", `{"folders":[{"id":"","name":"Ignored"}],"items":[{"type":1,"name":"A","folderId":""}]}`),

		// Case-insensitive keys, duplicates and unicode folding.
		bw("case_upper_top_level_keys", `{"ITEMS":[{"type":1,"name":"A"}],"FOLDERS":[]}`),
		bw("case_item_keys", `{"items":[{"TYPE":1,"Name":"Case","FolderID":"f","NOTES":"n","Fields":[{"NAME":"x","VALUE":"y"}]}],"Folders":[{"ID":"f","NAME":"Dir"}]}`),
		bw("case_login_keys", `{"items":[{"type":1,"name":"L","LOGIN":{"UserName":"u","PASSWORD":"p","Totp":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP","URIs":[{"URI":"https://a.test"}]}}]}`), // #nosec G101 -- public synthetic import fixture, not a real credential
		bw("case_card_keys", `{"items":[{"type":2,"name":"C","CARD":{"CardholderName":"Holder","NUMBER":"fixture-1","EXPMONTH":"01","expyear":"2031","CODE":"123"}}]}`),
		bw("case_exact_key_preferred", `{"items":[{"type":1,"NAME":"upper","name":"lower"}]}`),
		bw("case_exact_key_preferred_reversed", `{"items":[{"type":1,"name":"lower","NAME":"upper"}]}`),
		bw("case_unicode_fold_dotless_i", "{\"\u0131tems\":[{\"type\":1,\"name\":\"Fold\"}]}"),
		bw("case_unicode_fold_long_s", "{\"item\u017f\":[{\"type\":1,\"name\":\"Fold\"}]}"),
		bw("case_unicode_fold_kelvin_no_match", "{\"items\":[{\"type\":1,\"name\":\"A\",\"\u212aey\":1}]}"),
		bw("case_field_names_not_folded_in_output", `{"items":[{"type":1,"name":"A","fields":[{"name":"MixedCase","value":"1"},{"name":"mixedcase","value":"2"}]}]}`),
		bw("case_bad_type_with_variant_key", `{"items":[{"TYPE":"1"}]}`),
		bw("duplicate_items_key_last_wins", `{"items":[{"type":1,"name":"A"}],"items":[{"type":1,"name":"B"}]}`),
		bw("duplicate_items_key_reuses_elements", `{"items":[{"type":1,"name":"A","notes":"kept"},{"type":1,"name":"Second"}],"items":[{"type":1,"name":"B"}]}`),
		bw("duplicate_item_key_last_wins", `{"items":[{"type":1,"name":"A","name":"B"}]}`),
		bw("duplicate_login_merges", `{"items":[{"type":1,"name":"A","login":{"username":"u"},"login":{"password":"p"}}]}`),
		bw("duplicate_mixed_case_keys_last_wins", `{"items":[{"type":1,"name":"A","Name":"B","NAME":"C"}]}`),
		bw("duplicate_uris_reuses_elements", `{"items":[{"type":1,"name":"A","login":{"uris":[{"uri":"https://one.test"},{"uri":"https://two.test"}],"uris":[{}]}}]}`),
		bw("duplicate_fields_reuses_elements", `{"items":[{"type":1,"name":"A","fields":[{"name":"k","value":"v"}],"fields":[{"value":"w"}]}]}`),

		// Strings, escapes and path normalization.
		bw("string_escapes", `{"items":[{"type":1,"name":"a\u0041\/\t\"\\b","notes":"line1\nline2"}]}`),
		bw("string_surrogate_pair", `{"items":[{"type":1,"name":"emoji\ud83d\ude00"}]}`),
		bw("string_lone_high_surrogate", `{"items":[{"type":1,"name":"x\ud800y"}]}`),
		bw("string_lone_low_surrogate", `{"items":[{"type":1,"name":"x\udc00y"}]}`),
		bw("string_unicode_whitespace_path", "{\"items\":[{\"type\":1,\"name\":\"\u3000 a\u00a0b \u2003\"}]}"),
		bw("string_html_characters", `{"items":[{"type":1,"name":"a<b>&c","notes":"<x>&\u2028\u2029"}]}`),
		bw("string_path_traversal_and_specials", `{"items":[{"type":1,"name":"../a..b/./c*?\"<>|:\\d"}]}`),
		bw("string_dots_only_name", `{"items":[{"type":1,"name":"....."}]}`),

		// Fields, TOTP and card/login differences.
		bw("fields_override_builtin_keys", `{"items":[{"type":1,"name":"A","login":{"username":"u","password":"p"},"fields":[{"name":"password","value":"override"},{"name":"url","value":"u"},{"name":"urls","value":"not-a-list"}]}]}`),
		bw("fields_duplicate_names_last_wins", `{"items":[{"type":1,"name":"A","fields":[{"name":"k","value":"1"},{"name":"k","value":"2"}]}]}`),
		bw("fields_totp_case_variants", `{"items":[{"type":1,"name":"A","fields":[{"name":"ToTp","value":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}]}]}`), // #nosec G101 -- public synthetic import fixture, not a real credential
		bw("fields_totp_empty_value_skipped", `{"items":[{"type":1,"name":"A","fields":[{"name":"totp","value":""}]}]}`),
		bw("fields_totp_invalid_warning", `{"items":[{"type":1,"name":"A","fields":[{"name":"TOTP","value":"not-base32!"}]}]}`),
		bw("login_totp_invalid_warning", `{"items":[{"type":1,"name":"A","login":{"totp":"bad"}}]}`),
		bw("login_totp_and_field_both_invalid", `{"items":[{"type":1,"name":"A","login":{"totp":"bad-login"},"fields":[{"name":"totp","value":"bad-field"}]}]}`),
		bw("login_totp_overrides_valid_field", `{"items":[{"type":1,"name":"A","login":{"totp":"otpauth://totp/x?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&digits=8"},"fields":[{"name":"totp","value":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}]}]}`), // #nosec G101 -- public synthetic import fixture, not a real credential
		bw("login_invalid_totp_keeps_valid_field", `{"items":[{"type":1,"name":"A","login":{"totp":"bad"},"fields":[{"name":"totp","value":"JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"}]}]}`),                                                           // #nosec G101 -- public synthetic import fixture, not a real credential
		bw("card_totp_field_is_plain", `{"items":[{"type":2,"name":"C","card":{"number":"fixture-1"},"fields":[{"name":"totp","value":"bad"},{"name":"extra","value":"e"}]}]}`),
		bw("card_login_block_ignored", `{"items":[{"type":2,"name":"C","login":{"username":"u","totp":"bad"},"notes":"ignored"}]}`),
		bw("login_card_block_ignored", `{"items":[{"type":1,"name":"L","card":{"number":"fixture-1"}}]}`),
		bw("card_fields_override_builtin_keys", `{"items":[{"type":2,"name":"C","card":{"number":"fixture-1"},"fields":[{"name":"card_number","value":"override"},{"name":"subtype","value":"x"}]}]}`),
		bw("login_uris_empty_first", `{"items":[{"type":1,"name":"A","login":{"uris":[{"uri":""},{"uri":"https://b.test"},{}]}}]}`),
		bw("login_uris_all_empty", `{"items":[{"type":1,"name":"A","login":{"uris":[{},{"uri":""}]}}]}`),
		bw("item_kinds_mixed", `{"items":[{"type":1,"name":"L"},{"type":2,"name":"C"},{"type":3,"name":"Note"},{"type":4,"name":"Identity"},{"type":1,"name":"L2"}]}`),
		bw("unknown_keys_everywhere", `{"version":2,"encrypted":false,"folders":[{"id":"f","name":"F","extra":[1,2]}],"items":[{"type":1,"name":"A","folderId":"f","favorite":true,"login":{"uris":[{"uri":"https://a.test","match":null}],"extra":{}},"collectionIds":null,"revisionDate":"2024-01-01T00:00:00.000Z"}]}`),
	}
}

export type ParamType = "system" | "event" | "ajax" | "user";
export type TabId = "intercept" | "fetch" | "viewstate";

export interface ViewStateInfo {
  value?: unknown;
  error?: string;
  partial?: boolean;
  mac_present?: boolean;
  mac_bytes?: string;
  mac_length?: number;
  mac_algorithm?: string;
  total_bytes?: number;
  serialized_bytes?: number;
  base64_length?: number;
  hex_preview?: string;
}

export interface Param {
  name: string;
  raw_name: string;
  value: string;
  raw_value: string;
  type: ParamType;
  editable: boolean;
  input_type?: string;
  viewstate?: ViewStateInfo;
  is_json?: boolean;
}

export interface ParsedRequest {
  method: string;
  path: string;
  url: string;
  http_version: string;
  headers: Record<string, string>;
  body: string;
  params: Param[];
  content_type: string;
  is_ajax: boolean;
  is_aspnet: boolean;
}

export interface AjaxPart {
  type: string;
  id: string;
  content: string;
  length: number;
  highlight?: boolean;
  viewstate_decoded?: ViewStateInfo;
  is_error?: boolean;
  redirect_url?: string;
}

export interface ReplayResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  is_ajax: boolean;
  ajax_parts: AjaxPart[];
  content_type: string;
  aspnet_error: boolean;
  viewstate_error: boolean;
}

export interface MacResult {
  mac_present_in_viewstate: boolean;
  mac_length?: number;
  mac_algorithm?: string;
  test_result: string;
  vulnerable?: boolean;
  message: string;
  response_status?: number;
  stripped_viewstate?: string;
}

export interface FetchedForm {
  action: string;
  method: string;
  params: Param[];
}

export interface FetchResult {
  url: string;
  status: number;
  forms: FetchedForm[];
  cookies: Record<string, string>;
  aspnet_session?: string;
}

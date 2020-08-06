import {
  validateAuthorizationCode,
  validateMultipleRedirectUriParams,
  validateParamValue,
  validateQueryParams,
  validateURIForFragment,
  validateURIForTLS,
  validateURIHttpMethod,
  sanitizeQueryParams,
  authorizeRequest,
} from './authorization-request';

export const AuthorizationRequest = {
  validateAuthorizationCode,
  validateMultipleRedirectUriParams,
  validateParamValue,
  validateQueryParams,
  validateURIForFragment,
  validateURIForTLS,
  validateURIHttpMethod,
  sanitizeQueryParams,
  authorizeRequest,
};

export { getRequest } from './utils';

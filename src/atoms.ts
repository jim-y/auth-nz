import {
  validateParamValue,
  validateQueryParams,
  validateURIForFragment,
  validateURIForTLS,
  validateURIHttpMethod,
  sanitizeQueryParams,
  authorizeRequest,
} from './authorization-request';

export const AuthorizationRequest = {
  validateParamValue,
  validateQueryParams,
  validateURIForFragment,
  validateURIForTLS,
  validateURIHttpMethod,
  sanitizeQueryParams,
  authorizeRequest,
};

export { getRequest } from './utils';

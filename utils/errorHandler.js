/**
 * Error Handling Utilities for API requests, network failures, and edge cases.
 */

export class ApiError extends Error {
  /**
   * @param {string} message 
   * @param {number|string} [statusCode] 
   * @param {string} [service] 
   */
  constructor(message, statusCode = null, service = 'Unknown') {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.service = service;
  }
}

/**
 * Translates fetch errors or HTTP status codes into helpful user messages.
 * @param {Error|ApiError|any} err 
 * @param {string} serviceName 
 * @returns {string}
 */
export function getFriendlyErrorMessage(err, serviceName = 'Service') {
  if (!err) return `${serviceName}: Data unavailable`;

  if (err.name === 'AbortError' || err.message?.includes('timeout')) {
    return `${serviceName} request timed out. Internet Archive or external server may be slow.`;
  }

  if (err.statusCode === 429) {
    return `${serviceName} rate limit exceeded. Please wait a moment before querying again.`;
  }

  if (err.statusCode === 401 || err.statusCode === 403) {
    return `${serviceName} authentication failed. Please verify your API key in Settings.`;
  }

  if (err.statusCode === 404) {
    return `No records found in ${serviceName}.`;
  }

  if (err.message && err.message.includes('Failed to fetch')) {
    return `Network connection failed or endpoint blocked by CORS/Adblocker.`;
  }

  return err.message || `${serviceName}: Data unavailable`;
}

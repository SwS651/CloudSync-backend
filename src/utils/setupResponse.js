// Helper to create a success response
 const createSuccessResponse = (data,message) => ({
    success: true,
    message: message || '',
    data,
});

// Helper to create an error response
 const createErrorResponse = (defaultMessage, errorMessage = '') => ({
    success: false,
    message: errorMessage || defaultMessage,
    data: {},
});

module.exports = {
    createSuccessResponse,
    createErrorResponse
}
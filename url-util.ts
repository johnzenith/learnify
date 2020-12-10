const env = require('./../config/clean-env');

/**
 * URL Utility
 */
class UrlUtil {
    public static readonly apiBaseUrl: string = `${env.URL_SCHEME}://[::1]:${env.PORT}/api/`;

}

module.exports = UrlUtil;

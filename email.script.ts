import { promises } from "fs";

const jwt                            = require('jsonwebtoken');
const env                            = require('./../config/clean-env');
const ip                             = require('ip');
const validator                      = require('validator');
const bcrypt                         = require('bcrypt');
const { Base64 }                     = require('js-base64');
const { DateTime }                   = require('luxon');
const StringUtil                     = require('./../helpers/StringUtil');
const RequestUtil                    = require('./../helpers/RequestUtil');
const UrlUtil                        = require('./../helpers/UrlUtil');

const UserController                 = require('./../helpers/UrlUtil');

const {
    User,
    UserMeta,
    UserBalance,
    UserActivity,
    UserStatistic,
    UserPreference,
    UserGeneralSetting,
    UserTransactionSetting
} = require('./../models').db;

const EmailController = {
    getEmailIndex(emailKey: string) {
        return `${emailKey}|${ip.address()}`;
    },

    async generateEmailHash(args: { userId: string, email: string, data: object, expiration: 30, errorMsg: string }) {
        const { errorMsg } = args;
        const _errorMsg = errorMsg ? errorMsg : 'Unable to send confirmation email';

        try {
            const { userId, email, expiration, data } = args;

            // email key
            const emailKey     = StringUtil.getUuid();
            const emailKeyHash = await bcrypt.hash(emailKey, 10);

            const userMetaData = await UserMeta.findOne({
                where: { user_id: userId },
                attributes: ['meta_data']
            });

            // Set the email access key index
            // emailKey|ip
            const emailAccessIndex = this.getEmailIndex(emailKey);

            const metaData  = userMetaData.get();
            const _metaData = Object.assign({}, JSON.parse(metaData), {
                [emailAccessIndex]: {
                    data,
                    emailKeyHash,
                    counter: 1,
                    seconds: 15,
                    targetSeconds: 15,
                    target: -1 // no limit
                },
                emailExpiration: DateTime.local().plus({ minutes: expiration })
            });

            // Save the email key resend time interval
            await UserMeta.update({ metaData: JSON.stringify(_metaData) }, {
                where: { user_id: userId }
            });

            // TODO: send email
            Base64.extendString();

            const encodeEmail     = Base64.encode(email);
            const encodeToken     = Base64.encode(StringUtil.getUuid());
            const encodeEmailKey  = Base64.encode(emailKey);

            const _encodeEmail    = Base64.fromUint8Array(Base64.toUint8Array(encodeEmail), true);
            const _encodeToken    = Base64.fromUint8Array(Base64.toUint8Array(encodeToken), true);
            const _encodeEmailKey = Base64.fromUint8Array(Base64.toUint8Array(encodeEmailKey), true);

            const emailUrlPath = `user/action/confirm/${_encodeEmail}/${_encodeEmailKey}/${_encodeToken}`;
            const emailUrl     = `${UrlUtil.apiBaseUrl}${emailUrlPath}`;

            console.log(emailUrl);
            return emailUrl;
        }
        catch (e) {
            throw _errorMsg;
        }
    },

    /**
     * Confirm user email action
     * @param string args
     *  - email
     *  - token 
     *  - key
     */
    async confirmEmailHash(args: { email: string, token: string, key: string }, callback: (userId, userData, data) => Promise<any>) {
        try {
            const { email, token, key } = args;
            
            // Decode the base64 strings
            Base64.extendString();
            
            const decodeKey   = Base64.decode(key);
            const decodeEmail = Base64.decode(email);
            const decodeToken = Base64.decode(token);

            const _key        = validator.escape(decodeKey);
            const _token      = validator.escape(decodeToken);
            const _email      = validator.normalizeEmail(decodeEmail);

            if (!Base64.isValid(_key) || !Base64.isValid(_token) || !validator.isEmail(_email)) {
                throw 'Email confirmation failed';
            }

            const emailAccessIndex = this.getEmailIndex(_key);

            const userData = await UserController.emailExists(_email, true);
            if ( !userData ) {
                throw 'Email does not exists';
            }

            const userId      = validator.escape(userData.user_id);

            const userProfile = await UserController.getProfile(
                userId, 'usermeta', { attributes: ['meta_data'] }
            );

            if (!userProfile) {
                throw 'Email address not associated with any account';
            }

            const metaData = userProfile['meta_data'];

            if (typeof metaData[emailAccessIndex] === 'undefined') {
                throw 'Unable to complete email verification';
            }

            const { emailKeyHash, data } = metaData[emailAccessIndex];
            const verifyEmailHash        = await bcrypt.compare(_key, emailKeyHash);

            if (!verifyEmailHash) {
                throw 'Email verification failed, please try again.';
            }

            // Everything seems ok, fire the callback
            (await callback).call(this, userId, data, userData);

            return {
                email,
                data,
                userData,
                updated: true
            };
        }
        catch (e) {
            console.log(e);
            StringUtil.throw(e, 'Email confirmation failed');
        }
    },

    /**
     * Remove the email index meta data
     */
    async removeEmailIndexMetaData(userId, key) {
        const emailAccessIndex = this.getEmailIndex(key);
        const userProfile      = await UserController.getProfile(
            userId, 'usermeta', { attributes: ['meta_data'] }
        );

        if (!userProfile) return false;

        const metaData = userProfile['meta_data'];

        if (typeof metaData[emailAccessIndex] === 'undefined') {
            return false;
        }

        delete metaData[emailAccessIndex];

        await UserMeta.update({ metaData }, {
            where: { userId }
        });
    }
};

module.exports = EmailController;

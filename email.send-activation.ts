    /**
     * Send user activation email
     * @param string email
     */
    async sendActivation(email: string) {
        try {
            const findUser = await User.findOne({
                where: {userEmail: email},
                attributes: ['user_id']
            });

            if (null === findUser) {
                throw 'Unable to send account activation email, please try again';
            }

            const userId = findUser.dataValues.user_id;

            // Activation key
            const activationKey     = StringUtil.getUuid();
            const activationKeyHash = await bcrypt.hash(activationKey, 10);

            // Save the activation key hash
            await User.update({ activationKey: activationKeyHash }, {
                where: { user_id: userId }
            });

             const userMetaData = await UserMeta.findOne({
                where: { user_id: userId },
                attributes: ['meta_data']
            });

            const metaData  = userMetaData.get();
            const _metaData = Object.assign({}, JSON.parse(metaData), {
                resendActivationLink: {
                    counter: 1,
                    seconds: 30,
                    targetSeconds: 120,
                    target: 5 // When counter gets to 5, use 120 seconds 
                },
                activationExpiration: DateTime.local().plus({ minutes: 10 })
            });

            // Save the activation key resend time interval
            await UserMeta.update({ metaData: JSON.stringify(_metaData) }, {
                where: { user_id: userId }
            });

            // TODO: send account activation email
            Base64.extendString();

            const encodeEmail          = Base64.encode(email);
            const encodeToken          = Base64.encode(StringUtil.getUuid());
            const encodeActivationKey  = Base64.encode(activationKey);

            const _encodeEmail         = Base64.fromUint8Array(Base64.toUint8Array(encodeEmail), true);
            const _encodeToken         = Base64.fromUint8Array(Base64.toUint8Array(encodeToken), true);
            const _encodeActivationKey = Base64.fromUint8Array(Base64.toUint8Array(encodeActivationKey), true);

            const activationUrlPath    = `user/activation/confirm/${_encodeEmail}/${_encodeActivationKey}/${_encodeToken}`;
            const activationUrl        = `${UrlUtil.apiBaseUrl}${activationUrlPath}`;

            console.log(activationUrl);

            return {
                email,
                success: true
            };
        }
        catch (e) {
            StringUtil.throw(e, 'Unable to send account activation email, please try again');
        }
    },

    /**
     * @protectedEndpoint
     * 
     * Confirm user activation email
     * @param string email
     * @param string key
     */
    async confirmActivation(email: string, key: string, token: string) {
        const errorMsg = 'Email confirmation failed';
        try {
            // Decode the base64 strings
            Base64.extendString();
            
            const decodeKey   = Base64.decode(key);
            const decodeEmail = Base64.decode(email);
            const decodeToken = Base64.decode(token);

            const _key        = validator.escape(decodeKey);
            const _token      = validator.escape(decodeToken);
            const _email      = validator.normalizeEmail(decodeEmail);

            if (!Base64.isValid(_key) || !Base64.isValid(_token) || !validator.isEmail(_email)) {
                throw errorMsg;
            }

            /**
             * Note: User must be logged in
             */
            const userData = await this.emailExists(_email, true);
            if ( !userData ) {
                throw errorMsg;
            }
            
            const { activation_key } = userData;
            const verifyEmailHash    = await bcrypt.compare(_key, activation_key);

            if (!verifyEmailHash) {
                throw 'Account activation token is invalid.';
            }

            return {
                email,
                activated: true
            };
        }
        catch (e) {
            console.log(e);
            StringUtil.throw(e, errorMsg);
        }
    },

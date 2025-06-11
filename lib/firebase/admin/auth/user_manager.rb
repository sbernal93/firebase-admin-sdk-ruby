module Firebase
  module Admin
    module Auth
      # Base url for the Google Identity Toolkit
      ID_TOOLKIT_URL = "https://identitytoolkit.googleapis.com/v1"

      # Provides methods for interacting with the Google Identity Toolkit
      class UserManager
        # Initializes a UserManager.
        #
        # @param [String] project_id The Firebase project id.
        # @param [Credentials] credentials The credentials to authenticate with.
        # @param [String, nil] url_override The base url to override with.
        def initialize(project_id, credentials, url_override = nil)
          uri = "#{url_override || ID_TOOLKIT_URL}/"
          @project_id = project_id
          @client = Firebase::Admin::Internal::HTTPClient.new(uri: uri, credentials: credentials)
        end

        # Creates a new user account with the specified properties.
        #
        # @param [String, nil] uid The id to assign to the newly created user.
        # @param [String, nil] display_name The user’s display name.
        # @param [String, nil] email The user’s primary email.
        # @param [Boolean, nil] email_verified A boolean indicating whether or not the user’s primary email is verified.
        # @param [String, nil] phone_number The user’s primary phone number.
        # @param [String, nil] photo_url The user’s photo URL.
        # @param [String, nil] password The user’s raw, unhashed password.
        # @param [Boolean, nil] disabled A boolean indicating whether or not the user account is disabled.
        #
        # @raise [CreateUserError] if a user cannot be created.
        #
        # @return [UserRecord]
        def create_user(uid: nil, display_name: nil, email: nil, email_verified: nil, phone_number: nil, photo_url: nil, password: nil, disabled: nil)
          payload = {
            localId: validate_uid(uid),
            displayName: validate_display_name(display_name),
            email: validate_email(email),
            phoneNumber: validate_phone_number(phone_number),
            photoUrl: validate_photo_url(photo_url),
            password: validate_password(password),
            emailVerified: to_boolean(email_verified),
            disabled: to_boolean(disabled)
          }.compact
          res = @client.post(with_path("accounts"), payload).body
          uid = res&.fetch("localId")
          raise CreateUserError, "failed to create user #{res}" if uid.nil?
          get_user_by(uid: uid)
        end

        # Gets the user corresponding to the provided key
        #
        # @param [Hash] query Query parameters to search for a user by.
        # @option query [String] :uid A user id.
        # @option query [String] :email An email address.
        # @option query [String] :phone_number A phone number.
        #
        # @return [UserRecord] A user or nil if not found
        def get_user_by(query)
          if (uid = query[:uid])
            payload = {localId: Array(validate_uid(uid, required: true))}
          elsif (email = query[:email])
            payload = {email: Array(validate_email(email, required: true))}
          elsif (phone_number = query[:phone_number])
            payload = {phoneNumber: Array(validate_phone_number(phone_number, required: true))}
          else
            raise ArgumentError, "Unsupported query: #{query}"
          end
          res = @client.post(with_path("accounts:lookup"), payload).body
          users = res["users"] if res
          UserRecord.new(users[0]) if users.is_a?(Array) && users.length > 0
        end

        # Deletes the user corresponding to the specified user id.
        #
        # @param [String] uid
        #   The id of the user.
        def delete_user(uid)
          @client.post(with_path("accounts:delete"), {localId: validate_uid(uid, required: true)})
        end

        def create_session_cookie(id_token, valid_duration = 432000)
          payload = {
            idToken: id_token,
            validDuration: valid_duration
          }
          @client.post("projects/#{@project_id}:createSessionCookie", payload).body
        end

        # Sets custom claims for a user.
        #
        # @param [String] uid The id of the user.
        # @param [Hash, nil] custom_claims The custom claims to set for the user. Pass nil to remove all custom claims.
        #
        # @raise [ArgumentError] if uid is missing or invalid.
        # @raise [SetCustomUserClaimsError] if the operation fails.
        def set_custom_user_claims(uid, custom_claims)
          payload = {
            localId: validate_uid(uid, required: true),
            customAttributes: custom_claims.nil? ? nil : custom_claims.to_json
          }
          res = @client.post(with_path("accounts:update"), payload).body
          raise SetCustomUserClaimsError, "failed to set custom claims: #{res}" if res&.fetch("localId", nil).nil?
          get_user_by(uid: uid)
        end

        # Updates an existing user account with the specified properties.
        #
        # @param [String] uid The ID of the user to update.
        # @param [Hash] params The user fields to update. Supported keys: :email, :display_name, :phone_number, :photo_url, :password, :email_verified, :disabled.
        #
        # @raise [UpdateUserError] if the user cannot be updated.
        #
        # @return [UserRecord]
        def update_user(uid, params = {})
          payload = {
            localId: validate_uid(uid, required: true),
            email: validate_email(params[:email]),
            displayName: validate_display_name(params[:display_name]),
            phoneNumber: validate_phone_number(params[:phone_number]),
            photoUrl: validate_photo_url(params[:photo_url]),
            password: validate_password(params[:password]),
            emailVerified: to_boolean(params[:email_verified]),
            disabled: to_boolean(params[:disabled])
          }.compact

          res = @client.post(with_path("accounts:update"), payload).body

          raise UpdateUserError, "failed to update user #{res}" if res&.fetch("localId", nil).nil?

          get_user_by(uid: uid)
        end

        private

        def with_path(path)
          "projects/#{@project_id}/#{path}"
        end

        include Utils
      end
    end
  end
end

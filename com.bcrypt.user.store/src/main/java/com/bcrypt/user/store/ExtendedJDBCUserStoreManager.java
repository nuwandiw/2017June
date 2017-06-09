package com.bcrypt.user.store;

import com.bcrypt.user.store.util.BCrypt;
import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.api.RealmConfiguration;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.claim.ClaimManager;
import org.wso2.carbon.user.core.jdbc.JDBCRealmConstants;
import org.wso2.carbon.user.core.jdbc.JDBCUserStoreManager;
import org.wso2.carbon.user.core.profile.ProfileConfigurationManager;
import org.wso2.carbon.user.core.util.DatabaseUtil;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.Secret;
import org.wso2.carbon.utils.UnsupportedSecretTypeException;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Map;

public class ExtendedJDBCUserStoreManager extends JDBCUserStoreManager {

    private static Log log = LogFactory.getLog(ExtendedJDBCUserStoreManager.class);

    protected static final String BCRYPT_HASH = "BCRYPT";
    protected static final String CASE_INSENSITIVE_USERNAME = "CaseInsensitiveUsername";
    protected static final String GENERATE_SALT_WORK_FACTOR = "GenerateSaltWorkFactor";

    public ExtendedJDBCUserStoreManager(){}

    public ExtendedJDBCUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties, ClaimManager
            claimManager, ProfileConfigurationManager profileManager, UserRealm realm, Integer tenantId)
            throws UserStoreException {
        super(realmConfig, properties, claimManager, profileManager, realm, tenantId);
    }

//    public ClimateJDBCUserStoreManager(RealmConfiguration realmConfig, int tenantId) throws UserStoreException {
//        super(realmConfig, tenantId);
//    }
//
//    public ClimateJDBCUserStoreManager(DataSource ds, RealmConfiguration realmConfig, int tenantId,
//                                       boolean addInitData) throws UserStoreException {
//
//        super(ds, realmConfig, tenantId, addInitData);
//    }
//
//    public ClimateJDBCUserStoreManager(DataSource ds, RealmConfiguration realmConfig)
//            throws UserStoreException {
//
//        super(ds, realmConfig);
//    }
//
//    /**
//     * @param realmConfig
//     * @param properties
//     * @param claimManager
//     * @param profileManager
//     * @param realm
//     * @param tenantId
//     * @param skipInitData
//     * @throws UserStoreException
//     */
//    public ClimateJDBCUserStoreManager(RealmConfiguration realmConfig, Map<String, Object> properties,
//                                ClaimManager claimManager, ProfileConfigurationManager profileManager, UserRealm realm,
//                                Integer tenantId, boolean skipInitData) throws UserStoreException {
//        super(realmConfig, properties, claimManager, profileManager, realm, tenantId, skipInitData);
//    }

    @Override
    protected String preparePassword(Object password, String saltValue) throws UserStoreException {

        String digestFunction = realmConfig.getUserStoreProperties().get(
                JDBCRealmConstants.DIGEST_FUNCTION);

        return getHashedPassword(password, digestFunction, saltValue);

    }

    private String getHashedPassword(Object password, String hashingAlgo, String saltValue) throws UserStoreException {

        String passwordString = getPasswordString(password);
        if (BCRYPT_HASH.equalsIgnoreCase(hashingAlgo)) {
            return BCrypt.hashpw(passwordString, BCrypt.gensalt());
        }

        if(hashingAlgo != null) {
            if(hashingAlgo.equals(UserCoreConstants.RealmConfig.PASSWORD_HASH_METHOD_PLAIN_TEXT)) {
                return passwordString;
            }

            Secret credentialObj;

            try {
                credentialObj = Secret.getSecret(password);
            } catch (UnsupportedSecretTypeException e) {
                throw new UserStoreException("Unsupported credential type", e);
            }
            if (saltValue != null) {
                credentialObj.addChars(saltValue.toCharArray());
            }

            MessageDigest digest = null;
            try {
                digest = MessageDigest.getInstance(hashingAlgo);
                byte[] byteValue = digest.digest(credentialObj.getBytes());
                passwordString = Base64.encode(byteValue);
            } catch (NoSuchAlgorithmException e) {
                throw new UserStoreException("Error while preparing password hash", e);
            }
        }
        return passwordString;
    }

    public boolean doAuthenticate(String userName, Object credential) throws UserStoreException {

        if (!checkUserNameValid(userName)) {
            return false;
        }

        if (!checkUserPasswordValid(credential)) {
            return false;
        }

        if (UserCoreUtil.isRegistryAnnonymousUser(userName)) {
            log.error("Anonnymous user trying to login");
            return false;
        }

        Connection dbConnection = null;
        ResultSet rs = null;
        PreparedStatement prepStmt = null;
        String sqlstmt = null;
        String password = null;
        boolean isAuthed = false;

        try {
            dbConnection = getDBConnection();
            dbConnection.setAutoCommit(false);

            if (isCaseSensitiveUsername()) {
                sqlstmt = realmConfig.getUserStoreProperty(JDBCRealmConstants.SELECT_USER);
            } else {
                sqlstmt = realmConfig.getUserStoreProperty(CASE_INSENSITIVE_USERNAME);
            }

            if (log.isDebugEnabled()) {
                log.debug(sqlstmt);
            }

            prepStmt = dbConnection.prepareStatement(sqlstmt);
            prepStmt.setString(1, userName);
            if (sqlstmt.contains(UserCoreConstants.UM_TENANT_COLUMN)) {
                prepStmt.setInt(2, tenantId);
            }

            rs = prepStmt.executeQuery();

            if (rs.next() == true) {
                String storedPassword = rs.getString(3);
                String saltValue = null;
                if ("true".equalsIgnoreCase(realmConfig
                        .getUserStoreProperty(JDBCRealmConstants.STORE_SALTED_PASSWORDS))) {
                    saltValue = rs.getString(4);
                }

                boolean requireChange = rs.getBoolean(5);
                Timestamp changedTime = rs.getTimestamp(6);

                GregorianCalendar gc = new GregorianCalendar();
                gc.add(GregorianCalendar.HOUR, -24);
                Date date = gc.getTime();

                if (requireChange == true && changedTime.before(date)) {
                    isAuthed = false;
                } else {
                    String digestFunction = realmConfig.getUserStoreProperties().get(
                            JDBCRealmConstants.DIGEST_FUNCTION);
                    if (BCRYPT_HASH.equalsIgnoreCase(digestFunction)) {
                        password = getPasswordString(credential);
                        isAuthed = BCrypt.checkpw(password, storedPassword);
                    } else {
                        password = this.preparePassword(credential, saltValue);
                        if ((storedPassword != null) && (storedPassword.equals(password))) {
                            isAuthed = true;
                        }
                    }
                }
            }
        } catch (SQLException e) {
            String msg = "Error occurred while retrieving user authentication info for user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException("Authentication Failure", e);
        } finally {
            DatabaseUtil.closeAllConnections(dbConnection, rs, prepStmt);
        }

        if (log.isDebugEnabled()) {
            log.debug("User " + userName + " login attempt. Login success :: " + isAuthed);
        }

        return isAuthed;
    }

    protected boolean isCaseSensitiveUsername() {
        String isUsernameCaseInsensitiveString = realmConfig.getUserStoreProperty(CASE_INSENSITIVE_USERNAME);
        return !Boolean.parseBoolean(isUsernameCaseInsensitiveString);
    }

    protected String getPasswordString(Object password) throws UserStoreException {
        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(password);
            return new String(credentialObj.getChars());
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }
    }

    protected String generateSaltValue() {
        String wfString =  realmConfig.getUserStoreProperty(GENERATE_SALT_WORK_FACTOR);

        int wf = 0;
        try {
            wf = Integer.valueOf(wfString);
        } catch (NumberFormatException e) {
            //ignore
            if (log.isDebugEnabled()) {
                log.debug("Could not parse " + wfString + " to integer");
            }
        }

        String saltValue = null;
        if (wf > 0) {
            return BCrypt.gensalt(wf);
        } else {
            return BCrypt.gensalt();
        }
    }

    @Override
    protected void persistUser(String userName, Object credential, String[] roleList,
                               Map<String, String> claims, String profileName, boolean requirePasswordChange)
            throws UserStoreException {

        Connection dbConnection = null;
        try{
            dbConnection = getDBConnection();
        }catch (SQLException e){
            String errorMessage = "Error occurred while getting DB connection";
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        }

        Secret credentialObj;
        try {
            credentialObj = Secret.getSecret(credential);
        } catch (UnsupportedSecretTypeException e) {
            throw new UserStoreException("Unsupported credential type", e);
        }

        try {
            String sqlStmt1 = realmConfig.getUserStoreProperty(JDBCRealmConstants.ADD_USER);

            String saltValue = null;

            if ("true".equalsIgnoreCase(realmConfig.getUserStoreProperties()
                    .get(JDBCRealmConstants.STORE_SALTED_PASSWORDS))) {
                saltValue = generateSaltValue();
            }

            String password = this.preparePassword(credentialObj, saltValue);

            // do all 4 possibilities
            if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue == null)) {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userName, password, "",
                        requirePasswordChange, new Date(), tenantId);
            } else if (sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) && (saltValue != null)) {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userName, password,
                        saltValue, requirePasswordChange, new Date(),
                        tenantId);
            } else if (!sqlStmt1.contains(UserCoreConstants.UM_TENANT_COLUMN) &&
                    (saltValue == null)) {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userName, password, "",
                        requirePasswordChange, new Date());
            } else {
                this.updateStringValuesToDatabase(dbConnection, sqlStmt1, userName, password, saltValue,
                        requirePasswordChange, new Date());
            }

            dbConnection.commit();
        } catch (Exception e) {
            try {
                dbConnection.rollback();
            } catch (SQLException e1) {
                String errorMessage = "Error rollbacking add user operation for user : " + userName;
                if (log.isDebugEnabled()) {
                    log.debug(errorMessage, e1);
                }
                throw new UserStoreException(errorMessage, e1);
            }
            String errorMessage = "Error while persisting user : " + userName;
            if (log.isDebugEnabled()) {
                log.debug(errorMessage, e);
            }
            throw new UserStoreException(errorMessage, e);
        } finally {
            credentialObj.clear();
            DatabaseUtil.closeAllConnections(dbConnection);
        }
    }

    /**
     * @param dbConnection
     * @param sqlStmt
     * @param params
     * @throws UserStoreException
     */
    private void updateStringValuesToDatabase(Connection dbConnection, String sqlStmt,
                                              Object... params) throws UserStoreException {
        PreparedStatement prepStmt = null;
        boolean localConnection = false;
        try {
            if (dbConnection == null) {
                localConnection = true;
                dbConnection = getDBConnection();
            }
            prepStmt = dbConnection.prepareStatement(sqlStmt);
            if (params != null && params.length > 0) {
                for (int i = 0; i < params.length; i++) {
                    Object param = params[i];
                    if (param == null) {
                        throw new UserStoreException("Invalid data provided");
                    } else if (param instanceof String) {
                        prepStmt.setString(i + 1, (String) param);
                    } else if (param instanceof Integer) {
                        prepStmt.setInt(i + 1, (Integer) param);
                    } else if (param instanceof Date) {
                        // Timestamp timestamp = new Timestamp(((Date) param).getTime());
                        // prepStmt.setTimestamp(i + 1, timestamp);
                        prepStmt.setTimestamp(i + 1, new Timestamp(System.currentTimeMillis()));
                    } else if (param instanceof Boolean) {
                        prepStmt.setBoolean(i + 1, (Boolean) param);
                    }
                }
            }
            int count = prepStmt.executeUpdate();

            if (log.isDebugEnabled()) {
                if (count == 0) {
                    log.debug("No rows were updated");
                }
                log.debug("Executed query is " + sqlStmt + " and number of updated rows :: "
                        + count);
            }

            if (localConnection) {
                dbConnection.commit();
            }
        } catch (SQLException e) {
            String msg = "Error occurred while updating string values to database.";
            if (log.isDebugEnabled()) {
                log.debug(msg, e);
            }
            throw new UserStoreException(msg, e);
        } finally {
            if (localConnection) {
                DatabaseUtil.closeAllConnections(dbConnection);
            }
            DatabaseUtil.closeAllConnections(null, prepStmt);
        }
    }

}

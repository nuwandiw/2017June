package com.bcrypt.user.store.internal;

import com.bcrypt.user.store.ExtendedJDBCUserStoreManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tracker.UserStoreManagerRegistry;

/**
 * @scr.component name="com.climate.user.store.internal.component" immediate="true"
 * @scr.reference name="realm.service"
 * interface="org.wso2.carbon.user.core.service.RealmService"cardinality="1..1"
 * policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class ExtendedJDBCUserStoreManagerServiceComponent {
    private static Log log = LogFactory.getLog(ExtendedJDBCUserStoreManagerServiceComponent.class);

    private static RealmService realmService;

    protected void activate(ComponentContext ctxt) {

        try {
            UserStoreManager climateUserStoreManager = new ExtendedJDBCUserStoreManager();
            ctxt.getBundleContext().registerService(UserStoreManager.class.getName(), climateUserStoreManager, null);
            UserStoreManagerRegistry.init(ctxt.getBundleContext());
            log.info("ClimateUserStoreManager bundle activated successfully..");
        } catch (Exception e) {
            log.error("Failed to activate climateUserStoreManager ", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("CustomUserStoreManager bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        log.debug("Setting the Realm Service");
        ExtendedJDBCUserStoreManagerServiceComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        log.debug("UnSetting the Realm Service");
        ExtendedJDBCUserStoreManagerServiceComponent.realmService = null;
    }

    public static RealmService getRealmService() {
        return realmService;
    }
}

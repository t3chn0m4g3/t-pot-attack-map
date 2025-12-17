/**
 * Cache Bridge - Connection between dashboard cache and map
 * Provides functions for map.js to interact with the cache system
 */

// Global function to restore attack to map during cache restoration
window.restoreAttackToMap = function(event) {
    // This function will be called by dashboard.js during cache restoration
    // map.js can override this function to handle restored attacks
    console.log('[CACHE-BRIDGE] Attack restoration requested:', event);
    
    // If map.js has defined a restoration handler, use it
    if (typeof window.processRestoredAttack === 'function') {
        window.processRestoredAttack(event);
    }
};

// Global function to get cache statistics
window.getCacheStatistics = function() {
    if (window.attackMapDashboard && window.attackMapDashboard.attackCache) {
        return window.attackMapDashboard.attackCache.getStatistics();
    }
    return null;
};

// Global function to clear cache (for debugging)
window.clearAttackCache = function() {
    if (window.attackMapDashboard && window.attackMapDashboard.attackCache) {
        // Clear based on storage type
        if (window.attackMapDashboard.attackCache.storageType === 'indexeddb') {
            // Clear IndexedDB
            const deleteRequest = indexedDB.deleteDatabase('TPotAttackCache');
            deleteRequest.onsuccess = () => console.log('[CACHE] IndexedDB cleared');
            deleteRequest.onerror = (e) => console.error('[CACHE] Failed to clear IndexedDB:', e);
        } else {
            // Clear LocalStorage
            localStorage.removeItem('tpot_attack_cache');
            console.log('[CACHE] LocalStorage cleared');
        }
        
        return true;
    }
    return false;
};

console.log('[CACHE-BRIDGE] Cache bridge initialized');

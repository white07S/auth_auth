import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useReducer,
} from 'react';
import { getMe, heartbeat, login as loginApi, logout as logoutApi, refresh as refreshApi } from './api_auth';

const AuthContext = createContext(null);
const HEARTBEAT_INTERVAL_MS = 4 * 60 * 1000;

const initialState = {
  status: 'loading',
  user: null,
  roles: [],
  permissions: [],
  idleRemainingSec: null,
  error: null,
};

const reducer = (state, action) => {
  switch (action.type) {
    case 'loading':
      return { ...state, status: 'loading', error: null };
    case 'authenticated':
      return {
        status: 'authenticated',
        user: action.payload.user,
        roles: action.payload.roles,
        permissions: action.payload.permissions,
        idleRemainingSec: action.payload.idleRemainingSec,
        error: null,
      };
    case 'unauthenticated':
      return { ...initialState, status: 'unauthenticated' };
    case 'updateIdle':
      return { ...state, idleRemainingSec: action.payload };
    case 'error':
      return { ...state, status: 'error', error: action.payload };
    default:
      return state;
  }
};

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(reducer, initialState);

  const bootstrap = useCallback(async () => {
    dispatch({ type: 'loading' });
    try {
      const data = await getMe();
      if (data?.authenticated) {
        dispatch({
          type: 'authenticated',
          payload: {
            user: data.user,
            roles: data.roles ?? [],
            permissions: data.permissions ?? [],
            idleRemainingSec: data.idleRemainingSec ?? null,
          },
        });
      } else {
        dispatch({ type: 'unauthenticated' });
      }
    } catch (err) {
      if (err?.status === 401) {
        dispatch({ type: 'unauthenticated' });
        return;
      }
      dispatch({ type: 'error', payload: err?.message || 'Unable to contact auth service.' });
    }
  }, []);

  useEffect(() => {
    let isCurrent = true;
    (async () => {
      if (!isCurrent) return;
      await bootstrap();
    })();
    return () => {
      isCurrent = false;
    };
  }, [bootstrap]);

  useEffect(() => {
    if (state.status !== 'authenticated') {
      return undefined;
    }
    const timer = setInterval(async () => {
      try {
        const data = await heartbeat();
        if (data?.idleRemainingSec != null) {
          dispatch({ type: 'updateIdle', payload: data.idleRemainingSec });
        }
      } catch (err) {
        if (err?.status === 401) {
          dispatch({ type: 'unauthenticated' });
        } else {
          dispatch({ type: 'error', payload: err?.message || 'Heartbeat failed.' });
        }
      }
    }, HEARTBEAT_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [state.status]);

  const handleLogin = useCallback((redirectTarget) => {
    loginApi(redirectTarget);
  }, []);

  const handleLogout = useCallback(async () => {
    try {
      await logoutApi();
    } catch (err) {
      console.error('Logout failed', err);
    } finally {
      dispatch({ type: 'unauthenticated' });
    }
  }, []);

  const handleRefresh = useCallback(async () => {
    try {
      const result = await refreshApi();
      if (result?.idleRemainingSec != null) {
        dispatch({ type: 'updateIdle', payload: result.idleRemainingSec });
      }
      return result;
    } catch (err) {
      if (err?.status === 401) {
        dispatch({ type: 'unauthenticated' });
        return null;
      }
      dispatch({ type: 'error', payload: err?.message || 'Refresh failed.' });
      throw err;
    }
  }, []);

  const value = useMemo(
    () => ({
      status: state.status,
      loading: state.status === 'loading',
      error: state.error,
      authenticated: state.status === 'authenticated',
      user: state.user,
      roles: state.roles,
      permissions: state.permissions,
      idleRemainingSec: state.idleRemainingSec,
      login: handleLogin,
      logout: handleLogout,
      refresh: handleRefresh,
      reload: bootstrap,
    }),
    [state, handleLogin, handleLogout, handleRefresh, bootstrap]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};


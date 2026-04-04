'use client';

import {
  createContext,
  useContext,
  useState,
  useCallback,
  type ReactNode,
} from 'react';
import React from 'react';
import { api } from './api-client';
import type { User, AuthResponse, OrgInfo } from '@/types';

interface AuthState {
  user: User | null;
  token: string | null;
  organizations: OrgInfo[];
  activeOrg: OrgInfo | null;
}

interface AuthContextType extends AuthState {
  login: (response: AuthResponse) => void;
  logout: () => void;
  updateUser: (user: User) => void;
  switchOrg: (orgId: string) => Promise<void>;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AuthState>(() => {
    const token = api.getToken();
    return {
      user: null,
      token,
      organizations: [],
      activeOrg: null,
    };
  });

  const login = useCallback((response: AuthResponse) => {
    const token = response.access_token ?? null;
    api.setToken(token);

    const orgs: OrgInfo[] = Array.isArray(response.data?.organizations)
      ? response.data!.organizations
      : [];

    setState({
      user: response.user ?? null,
      token,
      organizations: orgs,
      activeOrg: orgs.length > 0 ? orgs[0] : null,
    });
  }, []);

  const logout = useCallback(() => {
    api.setToken(null);
    setState({
      user: null,
      token: null,
      organizations: [],
      activeOrg: null,
    });
  }, []);

  const updateUser = useCallback((user: User) => {
    setState((prev) => ({ ...prev, user }));
  }, []);

  const switchOrg = useCallback(
    async (orgId: string) => {
      const org = state.organizations.find((o) => o.id === orgId);
      if (org) {
        setState((prev) => ({ ...prev, activeOrg: org }));
      }
    },
    [state.organizations]
  );

  const value: AuthContextType = {
    ...state,
    login,
    logout,
    updateUser,
    switchOrg,
  };

  return React.createElement(AuthContext.Provider, { value }, children);
}

export function useAuth(): AuthContextType {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return ctx;
}

import React, { createContext, useContext, useEffect, useState } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '../supabaseClient';

interface AuthContextType {
  user: User | null;
  session: Session | null;
  role: 'Admin' | 'User' | null;
  isSuspended: boolean;
  loading: boolean;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [role, setRole] = useState<'Admin' | 'User' | null>(null);
  const [isSuspended, setIsSuspended] = useState<boolean>(false);
  const [loading, setLoading] = useState(true);

  const fetchProfileDetails = async (userId: string): Promise<{ role: 'Admin' | 'User'; is_suspended: boolean }> => {
    try {
      const { data, error } = await supabase
        .from('profiles')
        .select('role, is_suspended')
        .eq('id', userId)
        .maybeSingle();

      if (error) {
        console.error('Error fetching details from profile table:', error);
        return { role: 'User' as const, is_suspended: false };
      }

      if (data) {
        return {
          role: (data.role as 'Admin' | 'User') || 'User',
          is_suspended: !!data.is_suspended
        };
      }

      return { role: 'User' as const, is_suspended: false };
    } catch (err) {
      console.error('Error in fetchProfileDetails:', err);
      return { role: 'User' as const, is_suspended: false };
    }
  };

  useEffect(() => {
    // 1. Get initial session
    supabase.auth.getSession().then(async ({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      if (session?.user) {
        const details = await fetchProfileDetails(session.user.id);
        setRole(details.role);
        setIsSuspended(details.is_suspended);
      } else {
        setRole(null);
        setIsSuspended(false);
      }
      setLoading(false);
    });

    // 2. Listen for auth state changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (_event, newSession) => {
      setSession(newSession);
      setUser(newSession?.user ?? null);
      
      if (newSession?.user) {
        const details = await fetchProfileDetails(newSession.user.id);
        setRole(details.role);
        setIsSuspended(details.is_suspended);
      } else {
        setRole(null);
        setIsSuspended(false);
      }
      
      setLoading(false);
    });

    return () => {
      subscription.unsubscribe();
    };
  }, []);

  // Subscribe to real-time updates for current user's profile
  useEffect(() => {
    if (!user) return;

    const channel = supabase.channel(`profile_realtime_${user.id}`)
      .on('postgres_changes', { 
        event: 'UPDATE', 
        schema: 'public', 
        table: 'profiles',
        filter: `id=eq.${user.id}`
      }, (payload) => {
        const updated = payload.new as any;
        if (updated) {
          if (updated.role) setRole(updated.role);
          if (updated.is_suspended !== undefined) setIsSuspended(!!updated.is_suspended);
        }
      })
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [user]);

  const signOut = async () => {
    setLoading(true);
    await supabase.auth.signOut();
    setUser(null);
    setSession(null);
    setRole(null);
    setIsSuspended(false);
    setLoading(false);
  };

  return (
    <AuthContext.Provider value={{ user, session, role, isSuspended, loading, signOut }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};


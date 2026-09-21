// Connection details for the Sister Chat backend.
//
// The key below is the *publishable* key. It is meant to sit in public source: on
// its own it can read and write nothing, because every table demands an
// authenticated member and row-level security checks each request. The secrets that
// matter — passwords, private keys, room keys — never reach the server at all.

export const CONFIG = {
  url: "https://hlneebmpmjscwdydkcyu.supabase.co",
  anonKey: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImhsbmVlYm1wbWpzY3dkeWRrY3l1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODk5ODQ0MDYsImV4cCI6MjEwNTU2MDQwNn0.kdtLuvr_f-XGgoaRl4kgk0UOBcT3DJ6qEJTl3jAwKcw",
};

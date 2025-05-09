<script>
  import { onMount } from 'svelte';
  
  export let data; // This will receive data from +page.server.ts
  
  let userProfile = null;
  let loading = true;
  let error = null;
  
  onMount(async () => {
    try {
      // Fetch user profile
      const response = await fetch('/api/user-profile');
      const result = await response.json();
      
      if (result.authenticated) {
        userProfile = result.profile;
      } else {
        error = 'Not authenticated';
      }
    } catch (err) {
      error = err.message;
    } finally {
      loading = false;
    }
  });
</script>

<main>
  <h1>Dashboard</h1>
  
  {#if loading}
    <p>Loading...</p>
  {:else if error}
    <div class="error">
      <p>Error: {error}</p>
      <a href="/api/auth/login">Login</a>
    </div>
  {:else if userProfile}
    <div class="profile">
      <h2>Welcome, {userProfile.given_name || userProfile.name || 'User'}!</h2>
      
      <div class="user-info">
        <h3>Your Profile</h3>
        <pre>{JSON.stringify(userProfile, null, 2)}</pre>
      </div>
      
      <a href="/api/auth/logout" class="logout">Logout</a>
    </div>
  {:else}
    <div class="not-authenticated">
      <p>You need to be logged in to view this page.</p>
      <a href="/api/auth/login">Login</a>
    </div>
  {/if}
</main>

<style>
  main {
    max-width: 800px;
    margin: 0 auto;
    padding: 2rem;
  }
  
  .error {
    background-color: #ffebee;
    color: #c62828;
    padding: 1rem;
    border-radius: 4px;
    margin-bottom: 1rem;
  }
  
  .user-info {
    margin-top: 2rem;
  }
  
  pre {
    background-color: #f5f5f5;
    padding: 1rem;
    border-radius: 4px;
    overflow: auto;
    max-height: 400px;
  }
  
  a {
    display: inline-block;
    margin-top: 1rem;
    padding: 0.5rem 1rem;
    background-color: #4f46e5;
    color: white;
    text-decoration: none;
    border-radius: 4px;
  }
  
  a:hover {
    background-color: #4338ca;
  }
  
  .logout {
    background-color: #ef4444;
  }
  
  .logout:hover {
    background-color: #dc2626;
  }
</style> 
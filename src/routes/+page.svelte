<script>
	import { page } from '$app/stores';
	export let data;
</script>

<main>
	<h1>Welcome to SvelteKit with Kinde Authentication</h1>
	
	<div class="links">
		{#if data.authenticated}
			<a href="/dashboard" class="button">Go to Dashboard</a>
		{:else}
			<a href="/api/auth/login" class="button primary">Login</a>
			<a href="/api/auth/register" class="button secondary">Register</a>
		{/if}
		
	</div>
	
	<p>Authentication status: {data.authenticated ? 'Logged in' : 'Not logged in'}</p>

	<p>Visit <a href="https://svelte.dev/docs/kit">svelte.dev/docs/kit</a> to read the documentation</p>
</main>

<style>
	main {
		display: flex;
		flex-direction: column;
		align-items: center;
		justify-content: center;
		min-height: 100vh;
		padding: 1rem;
		text-align: center;
	}
	
	.links {
		margin: 2rem 0;
		display: flex;
		gap: 1rem;
	}
	
	.button {
		display: inline-block;
		padding: 0.5rem 1rem;
		background-color: #4f46e5;
		color: white;
		text-decoration: none;
		border-radius: 0.25rem;
		font-weight: 500;
	}
	
	.button:hover {
		background-color: #4338ca;
	}
	
	.secondary {
		background-color: #6b7280;
	}
	
	.secondary:hover {
		background-color: #4b5563;
	}
</style>

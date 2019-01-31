package auth

func makeTestConfig() *Config {
	store := makeTestUserStore()

	config := &Config{
		UserStore: store,
	}
	config.SetDefaults()

	return config
}

package seediso

func CreateUbuntuSeedISO(isoPath string) error {

	userData := []byte(`#cloud-config
users:
  - name: demo
    sudo: ALL=(ALL) NOPASSWD:ALL
    passwd: $6$HASH...
`)

	metaData := []byte(`instance-id: ubuntu-seed
local-hostname: ubuntu
`)

	iso := SeedISO{
		UserData: userData,
		MetaData: metaData,
	}

	if err := iso.Create(isoPath); err != nil {
		return err
	}
	return nil
}

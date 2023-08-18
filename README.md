# Encrypt and Decrypt messages in Go with RSA

## Usage

```bash
git clone https://github.com/sifatulrabbi/go-encryption-practice.git
```

## Build and run

```bash
# build
make build

# run
./build/app
```

Or if you just want to run it using Go

```bash
go run main.go
```

## Initialize keys

`[name]` Replace this with your desired name. But do not use spaces when in the name. If you don't specify a name it will create keys with then name `guest`

```bash
./build/app init --name [name]
```

## Communicate

Replace `[name]` with your name and `your message goes here` with you desired message.

### Encrypt

```bash
# encrypt message
./build/app encrypt --name [name] your message goes here
# output -> 2a1076a4c0...9012adb4f9c
```

### Decrypt

```bash
# decrypt msg
./build/app decrypt --name [name] 2a1076a4c0...9012adb4f9c
# output -> your message goes here
```

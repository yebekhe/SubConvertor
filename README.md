# SubConvertor

**SubConvertor** is a utility that can be used to convert V2Ray subscriptions into Clash, Clash.Meta, and Surfboard formats.

To use subconverter, first you need to upload the `src` folder to your desired folder. Then, you can use the following command to convert a V2Ray subscription into Clash format:

```
subconverter.com?url=https://dler.cloud/subscribe/ABCDE&type=clash
```

This will print converted Clash subscription.

You can also use the following command to convert a V2Ray subscription into Clash.Meta format:

```
subconverter.com?url=https://dler.cloud/subscribe/ABCDE&type=meta
```

This will create a new file called `ABCDE.meta` in the current directory. This file will contain the converted Clash.Meta subscription.

Finally, you can use the following command to convert a V2Ray subscription into Surfboard format:

```
subconverter.com?url=https://dler.cloud/subscribe/ABCDE&type=surfboard
```

This will create a new file called `ABCDE.surfboard` in the current directory. This file will contain the converted Surfboard subscription.

The `process` parameter can be used to control the output of subconverter. The following values are supported:

* `name`: Only print the names of the converted proxies.
* `full`: Get the full config of the converted proxies.
* `proxy`: Just give the proxy converted to the desired format.

For example, the following command will only print the names of the converted proxies:

```
subconverter.com?url=https://dler.cloud/subscribe/ABCDE&type=clash&process=name
```

The following command will get the full config of the converted proxies:

```
subconverter.com?url=https://dler.cloud/subscribe/ABCDE&type=clash&process=full
```

The following command will just give the proxy converted to Clash format:

```
subconverter.com?url=https://dler.cloud/subscribe/ABCDE&type=clash&process=empty
```

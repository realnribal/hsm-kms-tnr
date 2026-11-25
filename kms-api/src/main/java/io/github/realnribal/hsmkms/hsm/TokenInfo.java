package io.github.realnribal.hsmkms.hsm;

public record TokenInfo(
        String library,
        String cryptokiVersion,
        String manufacturerId,
        String libraryDescription,
        String tokenLabel,
        String tokenManufacturer,
        String tokenModel,
        String serialNumber) {
}

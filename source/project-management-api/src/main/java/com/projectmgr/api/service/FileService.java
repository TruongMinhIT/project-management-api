package com.projectmgr.api.service;

import com.projectmgr.api.dto.ApiMessageDto;
import com.projectmgr.api.dto.file.UploadFileDto;
import com.projectmgr.api.exception.BadRequestException;
import com.projectmgr.api.form.file.UploadFileForm;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.Arrays;
import java.util.List;

@Service
@Slf4j
public class FileService {
    static final String[] UPLOAD_TYPES = new String[]{"AVATAR", "LOGO", "SETTING"};
    static final String[] AVATAR_EXTENSION = new String[]{"jpeg", "jpg", "gif", "bmp", "png"};

    @Value("${file.upload-dir}")
    private String ROOT_DIRECTORY;

    public ApiMessageDto<UploadFileDto> storeFile(UploadFileForm uploadFileForm) {
        ApiMessageDto<UploadFileDto> apiMessageDto = new ApiMessageDto<>();
        try {
            boolean contains = Arrays.stream(UPLOAD_TYPES).anyMatch(uploadFileForm.getType()::equalsIgnoreCase);
            if (!contains) {
                throw new BadRequestException("ERROR-UPLOAD-TYPE-INVALID", "Type is required in AVATAR, LOGO, SETTING");
            }
            String fileName = StringUtils.cleanPath(uploadFileForm.getFile().getOriginalFilename());
            String extension = FilenameUtils.getExtension(fileName);
            if ((uploadFileForm.getType().equals("AVATAR") || uploadFileForm.getType().equals("LOGO"))
                    && !Arrays.stream(AVATAR_EXTENSION).anyMatch(extension::equalsIgnoreCase)) {
                throw new BadRequestException("ERROR-FILE-FORMAT-INVALID", "File format is invalid");
            }
            //upload to uploadFolder/TYPE/id
            String finalFile = uploadFileForm.getType() + "_" + RandomStringUtils.randomAlphanumeric(10) + "." + extension;
            String typeFolder = File.separator + uploadFileForm.getType();

            Path fileStorageLocation = Paths.get(ROOT_DIRECTORY + typeFolder).toAbsolutePath().normalize();
            Files.createDirectories(fileStorageLocation);
            Path targetLocation = fileStorageLocation.resolve(finalFile);
            Files.copy(uploadFileForm.getFile().getInputStream(), targetLocation, StandardCopyOption.REPLACE_EXISTING);
            UploadFileDto uploadFileDto = new UploadFileDto();
            uploadFileDto.setFilePath(typeFolder + File.separator + finalFile);
            apiMessageDto.setData(uploadFileDto);
            apiMessageDto.setMessage("Upload file success");
        } catch (IOException e) {
            log.error(e.getMessage(), e);
            apiMessageDto.setResult(false);
            apiMessageDto.setMessage("" + e.getMessage());
        }
        return apiMessageDto;
    }

    public Resource loadFileAsResource(String folder, String fileName) {

        try {
            Path fileStorageLocation = Paths.get(ROOT_DIRECTORY + File.separator + folder).toAbsolutePath().normalize();
            Path fP = fileStorageLocation.resolve(fileName).normalize();
            Resource resource = new UrlResource(fP.toUri());
            if (resource.exists()) {
                return resource;
            }
        } catch (MalformedURLException ex) {
            log.error(ex.getMessage(), ex);

        }
        return null;
    }

    public void deleteFile(String filePath) {
        if (!isDeletable(filePath)) {
            return;
        }
        File file = new File(ROOT_DIRECTORY + filePath);
        file.delete();
    }

    public void deleteFiles(List<String> filePaths) {
        for (String filePath : filePaths) {
            if (!isDeletable(filePath)) {
                continue;
            }
            File file = new File(ROOT_DIRECTORY + filePath);
            file.delete();
        }
    }

    private boolean isDeletable(String filePath) {
        if (!StringUtils.hasText(filePath)) {
            return false;
        }
        File file = new File(ROOT_DIRECTORY + filePath);
        return file.isFile();
    }
}

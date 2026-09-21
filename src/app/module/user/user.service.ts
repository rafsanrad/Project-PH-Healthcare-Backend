import { UploadApiResponse } from "cloudinary";
import { cloudinary } from "../../lib/cloudinary";
import { prisma } from "../../lib/prisma";

const uploadProfileImage = async (buffer: Buffer, userId: string) => {
  //retrive previous image if have
  const currentUser = await prisma.user.findUnique({
    where: {
      id: userId,
    },
    select: {
      imagePublicId: true,
      imageUrl: true,
    },
  });

  //set image 
  const cloudinaryResult = await new Promise<UploadApiResponse>(
    (resolve, reject) => {
      cloudinary.uploader
        .upload_stream(
          {
            resource_type: "auto",
          },
          async (error, result) => {
            if (error) {
              return reject(error);
            }
            if (!result) {
              return reject(new Error("No result returned from cloudinary"));
            }
            resolve(result);
          },
        )
        .end(buffer);
    },
  );

  const updatedUser = await prisma.user.update({
    where: {
      id: userId,
    },
    data: {
      imageUrl: cloudinaryResult?.secure_url,
      imagePublicId: cloudinaryResult?.public_id,
    },
    omit: {
      password: true,
    },
  });

  //deleting previous image
  if (currentUser?.imagePublicId && currentUser?.imageUrl) {
    await cloudinary.uploader.destroy(currentUser.imagePublicId);
  }

  return updatedUser;
};

export const UserServices = {
  uploadProfileImage,
};

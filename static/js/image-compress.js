/**
 * Downscale and re-encode an oversized image client-side before upload, so
 * a normal photo never gets rejected for size -- only genuinely huge images
 * need this at all. Returns the original file unchanged if it's already
 * within the limit, or if it can't be decoded as an image.
 */
(function (global) {
  'use strict';

  function loadImageElement(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = () => resolve({ img, url });
      img.onerror = reject;
      img.src = url;
    });
  }

  async function compressIfNeeded(file, maxBytes, maxDimension) {
    maxDimension = maxDimension || 1600;
    if (file.size <= maxBytes) return file;

    let img;
    let objectUrl;
    try {
      ({ img, url: objectUrl } = await loadImageElement(file));
    } catch (error) {
      return file; // not a decodable image; let server-side validation handle it
    }

    let { width, height } = img;
    if (width > maxDimension || height > maxDimension) {
      const scale = maxDimension / Math.max(width, height);
      width = Math.round(width * scale);
      height = Math.round(height * scale);
    }

    const canvas = document.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    canvas.getContext('2d').drawImage(img, 0, 0, width, height);
    URL.revokeObjectURL(objectUrl);

    let quality = 0.85;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      const blob = await new Promise((resolve) => canvas.toBlob(resolve, 'image/jpeg', quality));
      if (!blob) break;
      if (blob.size <= maxBytes || quality <= 0.4) {
        const baseName = (file.name || 'photo').replace(/\.[^.]+$/, '');
        return new File([blob], `${baseName}.jpg`, { type: 'image/jpeg' });
      }
      quality -= 0.15;
    }
    return file;
  }

  global.SharitImageCompress = { compressIfNeeded: compressIfNeeded };
})(window);

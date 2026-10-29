import { useState, useRef } from 'react';
import { Upload, X, FileText, Image as ImageIcon, AlertCircle } from 'lucide-react';
import { cn } from '../../lib/utils';

interface AttachmentUploaderProps {
  files: File[];
  onChange: (files: File[]) => void;
  maxFiles?: number;
  maxSizeBytes?: number;
  allowedExtensions?: string[];
  disabled?: boolean;
}

export function AttachmentUploader({
  files,
  onChange,
  maxFiles = 3,
  maxSizeBytes = 10 * 1024 * 1024, // 10MB
  allowedExtensions = ['.pdf', '.png', '.jpg', '.jpeg', '.txt', '.csv', '.json'],
  disabled = false,
}: AttachmentUploaderProps) {
  const [error, setError] = useState<string | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const forbiddenExtensions = ['.exe', '.dll', '.bat', '.cmd', '.ps1', '.sh', '.scr', '.js'];

  function validateAndAddFiles(incomingFiles: FileList | File[]) {
    setError(null);
    const newFiles: File[] = [...files];

    for (let i = 0; i < incomingFiles.length; i++) {
      const file = incomingFiles[i];
      const ext = '.' + file.name.split('.').pop()?.toLowerCase();

      // Check forbidden
      if (forbiddenExtensions.includes(ext)) {
        setError(`Security restriction: Executables and scripts (${ext}) cannot be uploaded.`);
        return;
      }

      // Check allowed
      if (!allowedExtensions.includes(ext)) {
        setError(`File type '${ext}' not allowed. Permitted: ${allowedExtensions.join(', ')}`);
        return;
      }

      // Check size
      if (file.size > maxSizeBytes) {
        setError(`File '${file.name}' exceeds the maximum allowed size of ${Math.round(maxSizeBytes / (1024 * 1024))}MB.`);
        return;
      }

      // Max files check
      if (newFiles.length >= maxFiles) {
        setError(`You can attach up to ${maxFiles} files.`);
        break;
      }

      newFiles.push(file);
    }

    onChange(newFiles);
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault();
    setIsDragging(false);
    if (disabled) return;
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndAddFiles(e.dataTransfer.files);
    }
  }

  function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.files && e.target.files.length > 0) {
      validateAndAddFiles(e.target.files);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  }

  function removeFile(index: number) {
    const updated = files.filter((_, i) => i !== index);
    onChange(updated);
    setError(null);
  }

  function formatSize(bytes: number) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }

  return (
    <div className="space-y-2">
      <div
        onDragOver={(e) => {
          e.preventDefault();
          if (!disabled) setIsDragging(true);
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        onClick={() => !disabled && fileInputRef.current?.click()}
        className={cn(
          'border-2 border-dashed rounded-xl p-4 text-center cursor-pointer transition-colors',
          isDragging ? 'border-blue-500 bg-blue-50/50' : 'border-slate-200 hover:border-slate-300 bg-slate-50/50',
          disabled && 'opacity-60 cursor-not-allowed'
        )}
      >
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          multiple
          accept={allowedExtensions.join(',')}
          onChange={handleFileChange}
          disabled={disabled}
        />
        <div className="flex flex-col items-center justify-center gap-1.5 text-slate-600">
          <Upload className="w-5 h-5 text-slate-400" />
          <p className="text-xs font-semibold text-slate-700">
            Click to upload or drag and drop logs, screenshots, or reports
          </p>
          <p className="text-[11px] text-slate-400">
            Supported: PDF, PNG, JPG, TXT, CSV, JSON (Max {Math.round(maxSizeBytes / (1024 * 1024))}MB per file)
          </p>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-1.5 text-xs text-rose-600 bg-rose-50 border border-rose-100 px-3 py-2 rounded-lg">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {files.length > 0 && (
        <div className="space-y-1.5 pt-1">
          {files.map((file, idx) => (
            <div
              key={idx}
              className="flex items-center justify-between p-2 rounded-lg bg-white border border-slate-200 text-xs shadow-xs"
            >
              <div className="flex items-center gap-2 min-w-0">
                {file.type.startsWith('image/') ? (
                  <ImageIcon className="w-4 h-4 text-blue-600 shrink-0" />
                ) : (
                  <FileText className="w-4 h-4 text-slate-500 shrink-0" />
                )}
                <span className="font-medium text-slate-800 truncate max-w-[200px] sm:max-w-xs">{file.name}</span>
                <span className="text-slate-400 text-[11px]">({formatSize(file.size)})</span>
              </div>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation();
                  removeFile(idx);
                }}
                className="p-1 text-slate-400 hover:text-rose-600 rounded-md hover:bg-slate-100 transition-colors"
                title="Remove file"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

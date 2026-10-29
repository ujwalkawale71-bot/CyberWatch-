import { useState, useRef, type DragEvent, type ChangeEvent, type FormEvent } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  UploadCloud,
  FileSearch,
  Search,
  AlertCircle,
  CheckCircle2,
  Loader2,
  File as FileIcon,
  Lock,
  Hash,
} from 'lucide-react';
import { scanService } from '../../services/scan.service';

export function FileSecurityScanner() {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [dragOver, setDragOver] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadProgress, setUploadProgress] = useState<number>(0);
  const [isUploading, setIsUploading] = useState<boolean>(false);
  const [currentStage, setCurrentStage] = useState<string>('');
  const [stagesList, setStagesList] = useState<Array<{ name: string; status: 'pending' | 'running' | 'done' | 'failed' }>>([
    { name: 'Upload & Validation', status: 'pending' },
    { name: 'Hashing & Identity (MD5/SHA1/SHA256/ssdeep)', status: 'pending' },
    { name: 'File Type & Magic Byte Analysis', status: 'pending' },
    { name: 'Shannon Entropy Calculation', status: 'pending' },
    { name: 'Strings & Indicator Extraction', status: 'pending' },
    { name: 'Deterministic Risk Evaluation', status: 'pending' },
  ]);

  const [hashSearchInput, setHashSearchInput] = useState<string>('');
  const [isSearchingHash, setIsSearchingHash] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const MAX_FILE_SIZE_MB = 25;
  const MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024;

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    setErrorMessage(null);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processSelectedFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileInputChange = (e: ChangeEvent<HTMLInputElement>) => {
    setErrorMessage(null);
    if (e.target.files && e.target.files.length > 0) {
      processSelectedFile(e.target.files[0]);
    }
  };

  const processSelectedFile = (file: File) => {
    if (file.size > MAX_FILE_SIZE_BYTES) {
      setErrorMessage(`File size (${(file.size / (1024 * 1024)).toFixed(2)} MB) exceeds the maximum limit of ${MAX_FILE_SIZE_MB} MB.`);
      setSelectedFile(null);
      return;
    }
    setSelectedFile(file);
    startScan(file);
  };

  const startScan = async (file: File) => {
    setIsUploading(true);
    setErrorMessage(null);
    setUploadProgress(0);
    setCurrentStage('Streaming file upload to isolated scanner...');

    // Initialize progress animation
    setStagesList([
      { name: 'Upload & Validation', status: 'running' },
      { name: 'Hashing & Identity (MD5/SHA1/SHA256/ssdeep)', status: 'pending' },
      { name: 'File Type & Magic Byte Analysis', status: 'pending' },
      { name: 'Shannon Entropy Calculation', status: 'pending' },
      { name: 'Strings & Indicator Extraction', status: 'pending' },
      { name: 'Deterministic Risk Evaluation', status: 'pending' },
    ]);

    try {
      // Simulate live stage feedback during processing
      const timer1 = setTimeout(() => {
        setStagesList((prev) =>
          prev.map((s, idx) => (idx === 0 ? { ...s, status: 'done' } : idx === 1 ? { ...s, status: 'running' } : s))
        );
        setCurrentStage('Calculating cryptographic SHA-256, MD5, and fuzzy identity hashes...');
      }, 500);

      const timer2 = setTimeout(() => {
        setStagesList((prev) =>
          prev.map((s, idx) => (idx <= 1 ? { ...s, status: 'done' } : idx === 2 ? { ...s, status: 'running' } : s))
        );
        setCurrentStage('Inspecting binary magic bytes, file signature, and extension alignment...');
      }, 1000);

      const timer3 = setTimeout(() => {
        setStagesList((prev) =>
          prev.map((s, idx) => (idx <= 2 ? { ...s, status: 'done' } : idx === 3 ? { ...s, status: 'running' } : s))
        );
        setCurrentStage('Computing overall and block Shannon byte entropy distribution...');
      }, 1500);

      const timer4 = setTimeout(() => {
        setStagesList((prev) =>
          prev.map((s, idx) => (idx <= 3 ? { ...s, status: 'done' } : idx === 4 ? { ...s, status: 'running' } : s))
        );
        setCurrentStage('Extracting printable ASCII / UTF-16 strings, APIs, and network indicators...');
      }, 2000);

      const result = await scanService.uploadFile(file, (percent) => {
        setUploadProgress(percent);
      });

      clearTimeout(timer1);
      clearTimeout(timer2);
      clearTimeout(timer3);
      clearTimeout(timer4);

      setStagesList((prev) => prev.map((s) => ({ ...s, status: 'done' })));
      setCurrentStage('Static file analysis complete! Redirecting to report...');

      setTimeout(() => {
        setIsUploading(false);
        navigate(`/reports/scans/${result.id}`, { state: { scan: result } });
      }, 600);
    } catch (err: any) {
      setIsUploading(false);
      setStagesList((prev) =>
        prev.map((s) => (s.status === 'running' ? { ...s, status: 'failed' } : s))
      );
      setErrorMessage(
        err.response?.data?.message ||
          err.message ||
          'Failed to upload and analyze the selected file. Please try again.'
      );
    }
  };

  const handleHashSearch = async (e: FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);

    const cleanHash = hashSearchInput.trim();
    if (!cleanHash || cleanHash.length !== 64) {
      setErrorMessage('Please enter a valid 64-character SHA-256 hash.');
      return;
    }

    setIsSearchingHash(true);
    try {
      const scan = await scanService.getScanBySha256(cleanHash);
      setIsSearchingHash(false);
      if (scan) {
        navigate(`/reports/scans/${scan.id}`, { state: { scan } });
      } else {
        setErrorMessage('No existing scan report found for this SHA-256 hash in the database.');
      }
    } catch (err: any) {
      setIsSearchingHash(false);
      setErrorMessage(
        err.response?.data?.message ||
          err.message ||
          'No scan found for this SHA-256 hash.'
      );
    }
  };

  return (
    <div className="space-y-8">
      {/* Header card */}
      <div className="bg-white border border-slate-200/90 rounded-3xl p-6 sm:p-8 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
          <div className="flex items-center gap-4">
            <div className="w-14 h-14 rounded-2xl bg-blue-50 border border-blue-100 flex items-center justify-center shrink-0">
              <FileSearch className="w-7 h-7 text-blue-600" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-2xl sm:text-3xl font-extrabold text-slate-900 tracking-tight">
                  File Security Scanner
                </h1>
                <span className="text-[11px] font-bold tracking-wider uppercase px-2.5 py-0.5 rounded-full bg-blue-100/70 text-blue-700 border border-blue-200">
                  Upload Only
                </span>
              </div>
              <p className="text-sm text-slate-500 mt-1">
                Static security analysis for local files. Zero execution, isolated parsing, cryptographic hashing & entropy verification.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Upload Dropzone Area */}
      <div className="bg-white border-2 border-slate-200 rounded-3xl p-6 sm:p-10 shadow-sm relative overflow-hidden">
        <div className="max-w-3xl mx-auto space-y-6 text-center">
          <div>
            <h2 className="text-xl sm:text-2xl font-bold text-slate-900">
              Upload File for Static Analysis
            </h2>
            <p className="text-xs sm:text-sm text-slate-500 mt-1">
              Select or drag and drop any local file. Analysis is strictly static and safely executed in memory/isolation.
            </p>
          </div>

          {/* Drag and Drop Zone */}
          <div
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => !isUploading && fileInputRef.current?.click()}
            className={`border-2 border-dashed rounded-3xl p-8 sm:p-12 transition-all cursor-pointer flex flex-col items-center justify-center gap-4 ${
              dragOver
                ? 'border-blue-500 bg-blue-50/50 scale-[1.01]'
                : 'border-slate-300 hover:border-blue-400 bg-slate-50/50 hover:bg-slate-50'
            } ${isUploading ? 'pointer-events-none opacity-80' : ''}`}
          >
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={handleFileInputChange}
              disabled={isUploading}
            />

            <div className="w-16 h-16 rounded-full bg-white border border-slate-200 shadow-sm flex items-center justify-center text-blue-600">
              <UploadCloud className="w-8 h-8" />
            </div>

            <div className="space-y-1">
              <p className="text-base sm:text-lg font-bold text-slate-800">
                Drop your file here, or{' '}
                <span className="text-blue-600 hover:underline">Choose File</span>
              </p>
              <p className="text-xs text-slate-500">
                Supports Executables, Documents, Archives, Scripts, Images, and generic binary formats (Max {MAX_FILE_SIZE_MB} MB)
              </p>
            </div>

            <button
              type="button"
              disabled={isUploading}
              className="inline-flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white text-xs sm:text-sm font-semibold px-5 py-2.5 rounded-xl shadow-sm transition-all"
            >
              <FileIcon className="w-4 h-4" />
              <span>Choose File to Scan</span>
            </button>
          </div>

          {/* Privacy and Security Notice */}
          <div className="bg-slate-50 border border-slate-200/80 rounded-2xl p-4 text-left flex items-start gap-3">
            <Lock className="w-4 h-4 text-slate-500 shrink-0 mt-0.5" />
            <div className="text-xs text-slate-600 space-y-1">
              <p className="font-semibold text-slate-700">Privacy & Static Execution Guarantee</p>
              <p className="text-slate-500 leading-relaxed">
                Your uploaded file is used for static analysis and is not permanently stored. The backend never executes uploaded binaries, macros, or scripts. After processing, CyberWatch retains hashes, analysis features, and security findings according to the configured retention policy.
              </p>
            </div>
          </div>

          {/* Error notification */}
          {errorMessage && (
            <div className="p-4 rounded-2xl bg-red-50 border border-red-200 text-red-800 text-xs sm:text-sm flex items-start gap-3 text-left">
              <AlertCircle className="w-4 h-4 text-red-600 shrink-0 mt-0.5" />
              <div className="flex-1">
                <span className="font-bold">Error: </span>
                <span>{errorMessage}</span>
              </div>
            </div>
          )}

          {/* Live Progress Card */}
          {isUploading && (
            <div className="bg-white border border-blue-100 rounded-2xl p-6 shadow-sm text-left space-y-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <Loader2 className="w-5 h-5 text-blue-600 animate-spin" />
                  <span className="text-sm font-bold text-slate-800">
                    {selectedFile ? selectedFile.name : 'Uploading sample...'}
                  </span>
                </div>
                <span className="text-xs font-semibold text-slate-500">
                  {uploadProgress > 0 && uploadProgress < 100 ? `${uploadProgress}% uploaded` : currentStage}
                </span>
              </div>

              {/* Progress bar */}
              <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden">
                <div
                  className="bg-blue-600 h-2 transition-all duration-300 rounded-full"
                  style={{ width: `${Math.max(uploadProgress, 25)}%` }}
                />
              </div>

              {/* Real Pipeline Stages List */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2">
                {stagesList.map((st, i) => (
                  <div
                    key={i}
                    className={`flex items-center gap-2 p-2 rounded-xl text-xs border ${
                      st.status === 'done'
                        ? 'bg-emerald-50/50 border-emerald-100 text-emerald-800'
                        : st.status === 'running'
                        ? 'bg-blue-50 border-blue-200 text-blue-800 font-semibold'
                        : st.status === 'failed'
                        ? 'bg-red-50 border-red-200 text-red-800'
                        : 'bg-slate-50 border-slate-100 text-slate-400'
                    }`}
                  >
                    {st.status === 'done' ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-emerald-600 shrink-0" />
                    ) : st.status === 'running' ? (
                      <Loader2 className="w-3.5 h-3.5 text-blue-600 animate-spin shrink-0" />
                    ) : st.status === 'failed' ? (
                      <AlertCircle className="w-3.5 h-3.5 text-red-600 shrink-0" />
                    ) : (
                      <div className="w-3.5 h-3.5 rounded-full border border-slate-300 shrink-0" />
                    )}
                    <span className="truncate">{st.name}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* SHA-256 Existing Report Search Card */}
      <div className="bg-white border border-slate-200 rounded-3xl p-6 sm:p-8 shadow-sm">
        <div className="max-w-3xl mx-auto space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-slate-100 border border-slate-200 flex items-center justify-center text-slate-700 shrink-0">
              <Hash className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base sm:text-lg font-bold text-slate-900">
                Search Stored Report by SHA-256
              </h3>
              <p className="text-xs text-slate-500">
                Query existing completed scan results by cryptographic SHA-256 fingerprint without uploading a file.
              </p>
            </div>
          </div>

          <form onSubmit={handleHashSearch} className="flex flex-col sm:flex-row gap-3 pt-2">
            <div className="relative flex-1">
              <Search className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={hashSearchInput}
                onChange={(e) => setHashSearchInput(e.target.value)}
                placeholder="Enter 64-character SHA-256 hash (e.g. e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855)"
                className="w-full bg-slate-50 border border-slate-200 focus:border-blue-500 focus:bg-white rounded-xl pl-10 pr-4 py-2.5 text-xs sm:text-sm text-slate-800 placeholder-slate-400 focus:outline-none transition-colors"
              />
            </div>
            <button
              type="submit"
              disabled={isSearchingHash || !hashSearchInput.trim()}
              className="inline-flex items-center justify-center gap-2 bg-slate-900 hover:bg-slate-800 disabled:bg-slate-300 text-white text-xs sm:text-sm font-semibold px-5 py-2.5 rounded-xl transition-all shadow-sm"
            >
              {isSearchingHash ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
              <span>Lookup Hash</span>
            </button>
          </form>
        </div>
      </div>

      {/* Supported File Formats Grid */}
      <div className="bg-slate-50/80 border border-slate-200 rounded-3xl p-6 sm:p-8">
        <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 mb-4">
          Supported Formats for Static Inspection
        </h4>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 text-xs">
          <div className="p-3 bg-white border border-slate-200 rounded-2xl">
            <p className="font-bold text-slate-900">Executables</p>
            <p className="text-slate-500 text-[11px] mt-0.5">EXE, DLL, SYS, PE, ELF, Mach-O</p>
          </div>
          <div className="p-3 bg-white border border-slate-200 rounded-2xl">
            <p className="font-bold text-slate-900">Documents</p>
            <p className="text-slate-500 text-[11px] mt-0.5">PDF, DOC, DOCX, XLS, XLSX, PPT, RTF</p>
          </div>
          <div className="p-3 bg-white border border-slate-200 rounded-2xl">
            <p className="font-bold text-slate-900">Archives</p>
            <p className="text-slate-500 text-[11px] mt-0.5">ZIP, RAR, 7Z, TAR, GZ</p>
          </div>
          <div className="p-3 bg-white border border-slate-200 rounded-2xl">
            <p className="font-bold text-slate-900">Scripts & Web</p>
            <p className="text-slate-500 text-[11px] mt-0.5">PS1, BAT, CMD, VBS, JS, SH, PY, HTML, HTA</p>
          </div>
          <div className="p-3 bg-white border border-slate-200 rounded-2xl">
            <p className="font-bold text-slate-900">Mobile & Disk</p>
            <p className="text-slate-500 text-[11px] mt-0.5">APK, JAR, ISO, IMG, LNK</p>
          </div>
          <div className="p-3 bg-white border border-slate-200 rounded-2xl">
            <p className="font-bold text-slate-900">Generic Binary</p>
            <p className="text-slate-500 text-[11px] mt-0.5">Entropy, magic bytes, strings</p>
          </div>
        </div>
      </div>
    </div>
  );
}

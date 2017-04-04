(function(document) {
    'use strict';

    // dom listeners and init
    document.addEventListener('DOMContentLoaded', function() {
        var fileUpload = document.getElementById('upload'),
            output     = document.getElementById('output');

        if(!File || !FileReader || !FileList || !DataView) {
            return document.getElementById('err').style.display = 'block';
        }

        fileUpload.addEventListener('change', function(e) {
            var peFile = e.target.files[0];

            if(peFile.type !== 'application/x-ms-dos-executable') {
                return output.innerHTML = 'filetype not supported...';
            }

            output.innerHTML = 'pe file!';

            var reader = new FileReader();
            reader.onloadend = function(e) {
                if(e.target.readyState === FileReader.DONE) {
                    parseFile(new DataView(reader.result));
                }
            }
            reader.readAsArrayBuffer(peFile);
        });
    });

    // pe parsing
    function parseFile(peDataView) {
        var pe = new BinStream(peDataView);

        try {
            var headers  = readHeaders(pe),
                dirs     = readDirectories(pe, headers);
                // sections = readSections(pe, headers);

            var dump = new HexDump({
                bytes:       headers.dos.stub,
                numCols:     16,
                element:     document.getElementById('hex'),
                startOffset: headers.dosSize - headers.dos.stub.length,
                caption:     'DOS Stub'
            });

            // var rdata = new HexDump({
            //     bytes: sections[0].raw,
            //     numCols: 32,
            //     element: document.getElementById('text'),
            //     startOffset: sections[0].offset,
            //     caption: '.rdata'
            // });

        } catch(e) {
            console.dir(e);
        }
    }

    function readHeaders(pe) {
        var dos        = dosHeader(pe),
            dosSize    = pe.bytesRead(),
            sig        = peSignature(pe),
            file       = fileHeader(pe),
            opt        = optionalHeader(pe),
            secHeaders = sectionHeaders(pe, file.NumberOfSections);

        return {
            dos:        dos,
            dosSize:    dosSize,
            rich:       parseRich(dos.stub),
            sig:        sig,
            file:       file,
            opt:        opt,
            secHeaders: secHeaders
        }
    }

    // stub
    function readDirectories(pe, headers) {
        var entries = ['export', 'import', 'resource', 'exception',
                       'security', 'baseReloc', 'debug', 'copyright',
                       'globalPtr', 'tls', 'loadConfig', 'boundImport',
                       'iatAddr', 'delayImportDescriptor', 'clrHeader'],
            dataDirectory = headers.opt.DataDirectory,
            validDirectories = {};

        for(var i = 0, len = entries.length; i < len; i++) {
            if(dataDirectory[i].Size) {
                validDirectories[entries[i]] = dataDirectory[i].VirtualAddress;
            }
        }

        return {};
    }

    function readSections(pe, headers) {
        var sectionHeaders = headers.secHeaders,
            numSections    = headers.file.NumberOfSections,
            sections       = new Array(numSections);

        for(var i = 0; i < numSections; i++) {
            var s    = sectionHeaders[i];

            sections[i] = {
                name:            s.Name,
                offset:          s.PointerToRawData,
                size:            s.SizeOfRawData,
                characteristics: parseCharacteristics(s.Characteristics)
            };

            sections[i].raw = pe.byte(s.SizeOfRawData, s.PointerToRawData);
        }

        return sections;
    }

    function parseCharacteristics(chars) {
        return {
            code:        chars & 0x00000020,
            idata:       chars & 0x00000040,
            bss:         chars & 0x00000080,
            nocache:     chars & 0x04000000,
            nopage:      chars & 0x08000000,
            shared:      chars & 0x10000000,
            executeable: chars & 0x20000000,
            readable:    chars & 0x40000000,
            writeable:   chars & 0x80000000
        };
    }

    function dosHeader(pe) {
        var dos = {
            e_magic:    pe.short(),
            e_cblp:     pe.short(),
            e_cp:       pe.short(),
            e_crlc:     pe.short(),
            e_cparhdr:  pe.short(),
            e_minalloc: pe.short(),
            e_maxalloc: pe.short(),
            e_ss:       pe.short(),
            e_sp:       pe.short(),
            e_csum:     pe.short(),
            e_ip:       pe.short(),
            e_cs:       pe.short(),
            e_lfarlc:   pe.short(),
            e_ovno:     pe.short(),
            e_res:      pe.short(4),
            e_oemid:    pe.short(),
            e_oeminfo:  pe.short(),
            e_res2:     pe.short(10),
            e_lfanew:   pe.int()
        };
        dos.stub = pe.byte(dos.e_lfanew - pe.bytesRead())

        return dos;
    }

    // todo: decrypt
    function parseRich(stub) {
        var richStart = 0x40,
            richEnd   = 0xa0;

        if(stub.slice(richEnd, richEnd + 4).map(byte2ASCII).join('') !== 'Rich') {
            return null;
        }

        // console.log('found rich!')
    }

    function peSignature(pe) { return pe.int(); }

    function fileHeader(pe) {
        return {
            Machine:              pe.short(),
            NumberOfSections:     pe.short(),
            TimeDateStamp:        pe.int(),
            PointerToSymbolTable: pe.int(),
            NumberOfSymbols:      pe.int(),
            SizeOfOptionalHeader: pe.short(),
            Characteristics:      pe.short()
        }
    }

    function optionalHeader(pe) {
        return {
            Magic:                        pe.short(),
            MajorLinkerVersion:           pe.byte(),
            MinorLinkerVersion:           pe.byte(),
            SizeOfCode:                   pe.int(),
            SizeOfInitializedData:        pe.int(),
            SizeOfUninitializedData:      pe.int(),
            AddressOfEntryPoint:          pe.int(),
            BaseOfCode:                   pe.int(),
            BaseOfData:                   pe.int(),
            ImageBase:                    pe.int(),
            SectionAlignment:             pe.int(),
            FileAlignment:                pe.int(),
            MajorOperatingSystemVersion:  pe.short(),
            MinorOperatingSystemVersion:  pe.short(),
            MajorImageVersion:            pe.short(),
            MinorImageVersion:            pe.short(),
            MajorSubsystemVersion:        pe.short(),
            MinorSubsystemVersion:        pe.short(),
            Reserved1:                    pe.int(),
            SizeOfImage:                  pe.int(),
            SizeOfHeaders:                pe.int(),
            CheckSum:                     pe.int(),
            Subsystem:                    pe.short(),
            DllCharacteristics:           pe.short(),
            SizeOfStackReserve:           pe.int(),
            SizeOfStackCommit:            pe.int(),
            SizeOfHeapReserve:            pe.int(),
            SizeOfHeapCommit:             pe.int(),
            LoaderFlags:                  pe.int(),
            NumberOfRvaAndSizes:          pe.int(),

            DataDirectory:                dataDirectories(pe)
        };
    }

    function dataDirectories(pe) {
        var numEntries = 16,    // IMAGE_NUMBEROF_DIRECTORY_ENTRIES
            dirs = new Array(numEntries);

        for(var i = 0; i < numEntries; i++) {
            dirs[i] = {
                VirtualAddress: pe.int(),
                Size:           pe.int()
            };
        }

        return dirs;
    }

    function sectionHeaders(pe, numSections) {
        var sectionNameLen = 8, // IMAGE_SIZEOF_SHORT_NAME
            sections = new Array(numSections);

        for(var i = 0; i < numSections; i++) {
            var section = {
                Name:                 pe.string(sectionNameLen),
                VirtualSize:          pe.int(),
                VirtualAddress:       pe.int(),
                SizeOfRawData:        pe.int(),
                PointerToRawData:     pe.int(),
                PointerToRelocations: pe.int(),
                PointerToLinenumbers: pe.int(),
                NumberOfRelocations:  pe.short(),
                NumberOfLinenumbers:  pe.short(),
                Characteristics:      pe.int()
            };
            section.PhysicalAddress = section.VirtualSize;  // union
            sections[i] = section;
        }

        return sections;
    }

    // function RVA(rva, bytesRead) { return rva - bytesRead; }

    // DataView stream abstraction
    function BinStream(dv) {
        var dvp = DataView.prototype;

        this.sbyte   = BinStream.readBytes.bind(this, dvp.getInt8,   1);
        this.byte    = BinStream.readBytes.bind(this, dvp.getUint8,  1);
        this.sshort  = BinStream.readBytes.bind(this, dvp.getInt16,  2);
        this.short   = BinStream.readBytes.bind(this, dvp.getUint16, 2);
        this.sint    = BinStream.readBytes.bind(this, dvp.getInt32,  4);
        this.int     = BinStream.readBytes.bind(this, dvp.getUint32, 4);

        this.dv     = dv;
        this.len    = dv.byteLength;
        this.offset = 0;
    }
    BinStream.prototype.skip = function(numBytes) { return this.offset += numBytes; }
    BinStream.prototype.bytesRead = function() { return this.offset; }
    BinStream.prototype.string = function(len) {
        var chars = this.byte(len);
        return String.fromCharCode.apply(null, chars);
    }

    BinStream.readBytes = function(func, cb, /* opt: */ num, absoluteOffset) {
        var offset = absoluteOffset || this.offset,
            f = func.bind(this.dv),
            ret;

        // num || absolute offset
        if(num) {
            ret = new Array(num);
            for(var i = 0; i < num; i++) {
                ret[i] = f(offset, true);
                offset += cb;
            }
        } else {
            ret = f(offset, true);
            offset += cb;
        }

        if(offset > this.len) {
            throw new BinStreamException('finished');
        }

        if(!absoluteOffset) {
            this.offset = offset;
        }

        return ret;
    }

    function BinStreamException(msg) {
        this.name = 'BinStreamException';
        this.message = msg;
        this.stack = (new Error()).stack;
    }
    BinStreamException.prototype = Object.create(Error.prototype);
    BinStreamException.prototype.constructor = BinStreamException;

    // hex component
    function HexDump(args) {
        // { bytes: array of bytes, numCols: # cols to display, element: container elem,
        //   startOffset: where to start location markers, caption: dump title }
        var numCols = args.numCols,
            bytes   = args.bytes,
            element = args.element,
            numRows = Math.ceil(bytes.length / numCols),
            table   = document.createElement('table'),
            cap     = document.createElement('caption'),
            offset  = args.startOffset;

        cap.appendChild(document.createTextNode(args.caption));
        table.appendChild(cap);

        hexDisplay:
        for(var row = 0; row < numRows; row++) {
            var tr        = document.createElement('tr'),
                rowIndex  = row*numCols,
                offsetCol = document.createElement('td');

            // offsetCol.appendChild(document.createTextNode(fixedWidthHex(offset)));
            offsetCol.appendChild(document.createTextNode(offset.toString(16)));
            offsetCol.className = 'hex-offset';
            tr.appendChild(offsetCol);
            offset += numCols;

            for(var col  = 0; col < numCols; col++) {
                var td   = document.createElement('td'),
                    byte = bytes[rowIndex + col];

                if(byte === undefined) {
                    break hexDisplay;
                }

                td.appendChild(document.createTextNode(fixedWidthHex(byte)));
                var suffix = kindOfByte(byte);
                if(suffix) {
                    td.className = 'hex-' + suffix;
                }

                tr.appendChild(td);
            }

            var rowText = bytes.slice(rowIndex, rowIndex + numCols).map(byte2ASCII).join(''),
                ascii = document.createElement('td');

            ascii.appendChild(document.createTextNode(rowText));
            ascii.className = 'hex-ascii';
            tr.appendChild(ascii);

            table.appendChild(tr);
        }

        element.appendChild(table);

        // element.addEventListener('mouseover', function(e) {
        //     if(e.relatedTarget.localName === 'td' &&
        //        e.className !== 'hex-offset'       &&
        //        e.className !== 'hex-ascii') {
        //         var cell   = e.fromElement,
        //             index  = cell.cellIndex,
        //             parent = cell.parentElement,
        //             ascii  = parent.children[parent.children.length - 1];
        //
        //         var newText = ascii.innerHTML.slice(0, index) +
        //                       '<em>' + ascii.innerHTML[index] + '</em>' +
        //                       ascii.innerHTML.slice(index);
        //         ascii.innerHTML = newText;
        //     }
        // }, false);

        this.rows  = numRows;
        this.cols  = numCols;
        this.size  = bytes.length;
        this.caption = args.caption;
    }

    function kindOfByte(byte) {
        if(byte == 0)
            return 'null';
        if(byte > 31 && byte < 127)
            return 'letter';
        return null;
    }

    function fixedWidthHex(num) {
        return ('0' + num.toString(16)).slice(-2);
    }

    function byte2ASCII(byte) {
        if(byte > 127 || byte < 32)
            return '.';
        return ' !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.'[byte - 32];
    }

}(window.document));

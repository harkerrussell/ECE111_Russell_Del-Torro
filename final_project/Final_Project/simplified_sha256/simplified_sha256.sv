module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input logic  clk, reset_n, start,
 input logic  [15:0] message_addr, output_addr,
 output logic done, mem_clk, mem_we, //for sharing the clk, and memory's write-enable
 output logic [15:0] mem_addr,
 output logic [31:0] mem_write_data,
 input logic [31:0] mem_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic [31:0] w[64]; //index each block 0-to-63
logic [31:0] message[20]; //index each block 0-to-19
logic [31:0] wt;
//logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;
logic [31:0] hh[8]; //output hash--easier to iterate than above line
logic [31:0] a, b, c, d, e, f, g, h;
logic [ 7:0] i, j;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;
logic [511:0] memory_block;
logic [ 7:0] tstep; //assigned later to (i-1)

logic [63:0] message_len; //used in function pad_last_block
logic [31:0] s1, s0; //used for word expansion in COMPUTE

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};


assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
assign tstep = (i - 1);

// ASSUMPTIONS: input must be 2^64 bits, Message processed in 512-bit blocks sequentially, digest is 256 bits

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch

function logic [15:0] determine_num_blocks(input logic [31:0] size); //size is param 'NUM_OF_WORDS'
  // Student to add function implementation

   // ======== START NUM-BLOCKS IMPLEMENTATION ========
   
   determine_num_blocks = (size/16) +1; //add 1 for truncated remainder, must pad later
   
   // ======== END NUM-BLOCKS IMPLEMENTATION ========

endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25); //Sum 1
    // Student to add remaning code below
    ch = (e&f) ^ ((~e)&g)//Choice Fxn
    t1 = h + S1 + ch + k[t] + w; //t corresponds to step (tstep)
    S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22); //Sum 0
    maj = (a&b) ^ (a&c) ^ (b&c)//Majority Fxn
    t2 = S0 + maj;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g}; //return new output hash
end
endfunction

// Word Expansion Function === is this legal???
//function logic [31:0] expand_words[64](input logic [31:0] in_words[16]);
//    begin
//       for(int the_t=0; the_t < 64; the_t++) begin
//          if(the_t < 16) begin
//             w[the_t] <= dpsram_tb[the_t]; //get input message and store in array
//          end //if
//          else begin
//             s0 <= rightrotate(w[the_t-15], 7) ^ rightrotate(w[the_t-15], 18) ^ (w[the_t-15] >> 3);
//             s1 <= rightrotate(w[the_t-2], 17) ^ rightrotate(w[the_t-2], 19) ^ (w[the_t-2] >> 10);
//             w[the_t] <= w[the_t-16] + s0 + w[the_t-7] + s1; //store the new expanded work
//          end //else
//       end //for
//    end
//endfunction


// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;


// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777

// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   // Student to add function implementation
   
   // ======== START RIGHT ROTATE IMPLEMENTATION ========
   // rotate last 'r' bits of input to front (left), shift the rest right by 'r' bits

   begin
      rightrotate = (x >> r) | (x << 32-r); 
   
   end
   
   // ======== END RIGHT ROTATE IMPLEMENTATION ========
   
endfunction

function logic [511:0] pad_last_block(input logic [512:0] init_block,
                                      input logic [ 63:0] msg_len);
   logic [511:0] the_pad = {1'b1,511'b0}; // a 1 bit, followed by 511 0 bits
   begin
      pad_last_block = {init_block[511:((j-1)*16)*32],the_pad[511:(NUM_OF_WORDS-((j-1)*16))*32],msg_len};
   end
endfunction


// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0; //read-only
    offset <= 0;
    j <= 1;
    i <= 1;
    state <= IDLE;
  end 
  else case (state)
    // ======================== IDLE STATE ======================== IDLE STATE ======================== 
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
       cur_we <= 1'b0;
       offset <= 0;
       // ======== initial hash values (stipulated by SHA256) ========
       hh[0] <= 32'h6a09e667;
       hh[1] <= 32'hbb67ae85;
       hh[2] <= 32'h3c6ef372;
       hh[3] <= 32'ha54ff53a;
       hh[4] <= 32'h510e527f;
       hh[5] <= 32'h9b05688c;
       hh[6] <= 32'h1f83d9ab;
       hh[7] <= 32'h5be0cd19;
       // -------- same for a,b,c,d,e,f,g,h for initial go --------
       a <= 32'h6a09e667;
       b <= 32'hbb67ae85;
       c <= 32'h3c6ef372;
       d <= 32'ha54ff53a;
       e <= 32'h510e527f;
       f <= 32'h9b05688c;
       g <= 32'h1f83d9ab;
       h <= 32'h5be0cd19;

       if(start) begin
       // Student to add rest of the code  
       state <= BLOCK; 
       end //if
       else begin //necessary to avoid latch inference?
          state <= IDLE;
       end //else
    end //end IDLE
    
    // ======================== BLOCK STATE ======================== BLOCK STATE ======================== 
    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
    BLOCK: begin
	// Fetch message in 512-bit block size
	// For each of 512-bit block initiate hash value computation
       
       offset <= offset + 1; //increment on next tick
       
       // initialize hash for next stage
       // first block will take initial values from IDLE 
       a <= hh[0];
       b <= hh[1];
       c <= hh[2];
       d <= hh[3];
       e <= hh[4];
       f <= hh[5];
       g <= hh[6];
       h <= hh[7];
       
       // tstep is (i-1)
       i <= i+1; //increments on next
       
       // === If we're on the first 16 rounds...
       //if(i <= 16) begin
       //
       //   // === do work expansion -- load message block into words 1-16 (0-15) as they are
       //   //w[tstep] <= mem_read_data;
       //   w[tstep] <= dpsram_tb[tstep]; // or should it be w[tstep] <= dpsram_tb[i] so correct will be available on next tick?
       //   // === run sha-op in compute
       //
       //end //if
       //// === Else, were in round 17-64, so sha, baby, sha!
       //else begin //
       //
       //   // === do expansion
       //   s0 <= rightrotate(w[i-15], 7) ^ rightrotate(w[i-15], 18) ^ (w[i-15] >> 3); //prep s0 for next tick?
       //   s1 <= rightrotate(w[i-2], 17) ^ rightrotate(w[i-2], 19) ^ (w[i-2] >> 10); //prep s1 for next tick?
       //   w[tstep] <= w[tstep-16] + s0 + w[tstep-7] + s1; //these will be using s0 and s1 from previous tick?
       //   // === run sha-op in compute
       //
       //end //else
       
       // === If we're not on the last block, let's just load the next 512 bits of message into memory_block
       if(j<num_blocks) begin
          memory_block <= message[(j*512)-1:(j-1)*512]; //j corresponds to message block number (index 1-to-num)blocks) better w/ offset?????
          i <= 1; //we want to reset 'i' and 'tstep' before COMPUTE
          state <= COMPUTE;
       end //if

       // === Else (we're on the last block), we need to pad with "1, 0...0, size"
       else begin 
          memory_block <= pad_last_block(message[(NUM_OF_WORDS*32)-1:((j-1)*512)], NUM_OF_WORDS*32); //not sure this is going to work :/?????
          i <= 1; //we want to reset 'i' and 'tstep' before COMPUTE
          // j will be reset after WRITE in IDLE state
          state <= COMPUTE;     
       end //else

    end //end BLOCK
    
    // ======================== COMPUTE STATE ======================== COMPUTE STATE ======================== 
    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE: begin
	
        // tstep is (i-1)
        i <= i+1; //increments on next
        
        //do word expansion ======== what to do about staggered assignment due to non-blocking assignment statements?????????????????????????
        for(int the_t=0; the_t < 64; the_t++) begin
           if(the_t < 16) begin
              w[the_t] <= memory_block[the_t*32]; //get input message and store in array
           end //if
           else begin
              s0 <= rightrotate(w[the_t-15], 7) ^ rightrotate(w[the_t-15], 18) ^ (w[the_t-15] >> 3);
              s1 <= rightrotate(w[the_t-2], 17) ^ rightrotate(w[the_t-2], 19) ^ (w[the_t-2] >> 10);
              w[the_t] <= w[the_t-16] + s0 + w[the_t-7] + s1; //store the new expanded work
           end //else
        end //for        
        
        // 64 processing rounds steps for 512-bit block 
        if (i <= 64) begin
          // === run sha-op
          {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[tstep], tstep); // (tstep is (i-1)) so indexing should be good
           state <= BLOCK;
        end //if
        else if(j < num_blocks) begin //if we have more blocks, save new hashes and go to process next BLOCK
           hh[0] <= hh[0] + a;
           hh[1] <= hh[1] + b;
           hh[2] <= hh[2] + c;
           hh[3] <= hh[3] + d;
           hh[4] <= hh[4] + e;
           hh[5] <= hh[5] + f;
           hh[6] <= hh[6] + g;
           hh[7] <= hh[7] + h;
           i <= 1; //we want to reset 'i' and 'tstep' 
           state <= BLOCK;
        end //else-if
        // === Else if this is the last block, save new hashes and go to WRITE the output
        else begin
           hh[0] <= hh[0] + a;
           hh[1] <= hh[1] + b;
           hh[2] <= hh[2] + c;
           hh[3] <= hh[3] + d;
           hh[4] <= hh[4] + e;
           hh[5] <= hh[5] + f;
           hh[6] <= hh[6] + g;
           hh[7] <= hh[7] + h;
           curr_we <= 1'b1;
           i <= 1; //we want to reset 'i' and 'tstep' 
           state <= WRITE;
        end //else
    end //end COMPUTE
    
    // ======================== WRITE STATE ======================== WRITE STATE ======================== 
    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin
   
    //set mem_we <= 1'b1; when appropriate (after last block is processed, upon exiting compute)
    //mem_adder is set by assign statement above (?)

    cur_write_data <= hh[tstep]; //write data
    i <= i +1; //iterator, remember tstep is i-1 -- reset in previous state if coming from BLOCK

    // === If we're within 0-to-7, continue 
    if(tstep<8) begin
       state <= WRITE;
    end //if
    else
       state <= IDLE; //will trigger 'done' signal as well in assign
       // j will be reset in IDLE
    end //else

    end //end WRITE
   endcase //state cases
  end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule // simplified_sha256 module
